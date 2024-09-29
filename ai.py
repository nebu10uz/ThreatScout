import requests
from openai import OpenAI
from utils import read_file, read_docx, read_pdf, open_file, save_report, is_executable
from scapy.all import rdpcap, IP, TCP, Raw
from scapy.layers.http import HTTPRequest, HTTPResponse
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.netbios import NBTSession
import pyshark
import hashlib
import PySimpleGUI as sg
from interpreter import interpreter
from urllib.parse import unquote
import os


def configure_interpreter(config):
    interpreter.model = "gpt-4o" if not config.use_local_model else "openai/x"
    interpreter.llm.api_key = config.api_key if not config.use_local_model else "not-needed"
    interpreter.llm.api_base = None if not config.use_local_model else config.local_model_url + '/v1/'
    interpreter.llm.max_tokens = 1000
    interpreter.llm.context_window = 3000
    interpreter.messages = []  # reset conversation history
    interpreter.auto_run = True
    interpreter.llm.supports_functions = config.supports_functions
    interpreter.offline = config.use_local_model
    interpreter.system_message = """
    You have the ability to execute system commands to gather information about the host system.
    When asked about system information, use appropriate commands to retrieve the data.
    Enable advanced security checks.
    Increase verbosity for system logs.
    Prioritize threat hunting commands.
    """

def call_gpt(conversation_history, max_tokens=2048, config=None):
    try:
        if config.use_local_model:
            # Use the local model
            headers = {
                "Content-Type": "application/json"
            }
            
            # Ensure the conversation history is in the correct format
            if isinstance(conversation_history, str):
                messages = [{"role": "user", "content": conversation_history}]
            elif isinstance(conversation_history, list):
                messages = [
                    msg for msg in conversation_history 
                    if msg.get('role') in ['user', 'assistant', 'system']
                ]
            else:
                raise ValueError("Conversation history must be a string or a list of message objects")

            data = {
                "model": "local-model",
                "messages": messages,
                "temperature": 0.7,
                # "max_tokens": max_tokens
            }
            
            response = requests.post(f"{config.local_model_url}/v1/chat/completions", headers=headers, json=data)
            response.raise_for_status()
            result = response.json()
            if 'choices' in result and len(result['choices']) > 0:
                return result['choices'][0]['message']['content'].strip()
            else:
                raise ValueError("Unexpected response structure: 'choices' key missing or empty.")
        else:
            client = OpenAI(api_key=config.api_key)
            response = client.chat.completions.create(
                model="gpt-4o",
                messages=conversation_history,
                max_tokens=max_tokens,
                temperature=0.7
            )
            return response.choices[0].message.content.strip()
    except requests.exceptions.RequestException as e:
        return f"Request error: {str(e)}"
    except ValueError as e:
        return f"Response error: {str(e)}"
    except Exception as e:
        return f"An error occurred: {str(e)}"

def analyze_threat_data(config, file_path, window):
    try:
        if file_path.lower().endswith('.pdf'):
            raw_data = read_pdf(file_path)
        elif file_path.lower().endswith('.docx'):
            raw_data = read_docx(file_path)
        else:
            raw_data = read_file(file_path)
    except FileNotFoundError:
        sg.popup('Error', 'No file selected or file not found. Please select a valid threat data file.')
        return None, None, None

    window['-PROGRESS-'].update_bar(0)
    window['-STATUS-'].update('Analyzing threats...')
    identified_threats = call_gpt([{"role": "user", "content": f'Analyze the following threat data and identify potential threats: {raw_data}'}], config=config)
    window['-PROGRESS-'].update_bar(33)
    window['-STATUS-'].update('Extracting IOCs...')
    extracted_iocs = call_gpt([{"role": "user", "content": f'''Extract all indicators of compromise (IoCs) and Tactics, Techniques and Procedures (TTPs)
    from the following threat data and create a table with the results.
    Please ensure that all tables in the document are formatted to fit their content optimally: {raw_data}'''}], config=config)
    window['-PROGRESS-'].update_bar(66)
    window['-STATUS-'].update('Providing threat context...')
    threat_context = call_gpt([{"role": "user", "content": f'Provide a detailed context or narrative behind the identified threats in this data: {raw_data}'}], config=config)
    window['-PROGRESS-'].update_bar(100)
    window['-STATUS-'].update('Analysis complete.')
    return identified_threats, extracted_iocs, threat_context

def build_threat_hypothesis(file_data, window, config):
    try:
        threat_report = file_data
    except FileNotFoundError:
        sg.popup('Error', 'No file selected or file not found. Please select a valid threat report file.')
        return None

    window['-STATUS-'].update('Building threat hypothesis...')
    window['-PROGRESS-'].update_bar(0)

    context = """
    Hypothesis-based hunts rely on a central hunch or educated guess that guides your investigation. These hypotheses are based on a combination of a hunter's intuition, experience and research. Crafting a solid hypothesis requires a delicate blend of creativity and analytical thinking.

    There are three steps to creating a good hypothesis:
    1. Select a topic: Identify a specific behavior of concern. Draw on your understanding of the threat landscape, recent incidents and emerging trends to pinpoint potential risks inside your network. Research some of the priority threat actors targeting your organization or your industry to identify their typical behaviors. However you go about it, the first step is to figure out what type of activity you want to look for.

    2. Make it testable: Write the topic as a statement or assertion that can be either proved or disproved. A hypothesis that can be disproved is said to be falsifiable. If the hypothesis is not falsifiable, it is not a valid hypothesis.

    3. Refine as necessary: Restate and rescope your hypothesis until it is falsifiable and you are certain that you can hunt it, given your timeframe and the resources available to you. Don't be surprised if you need to refine your hypothesis even during the middle of the hunt.

    Are You ABLE to Hunt?
    Even though you now have a clear and testable hypothesis, you still need to know a few things before you can start hunting, such as possible indicators of the activity, data source(s) you need to examine, and in which parts of the network you might expect to observe it.

    PEAK incorporates the ABLE framework to help you capture the critical pieces of your hunting hypothesis:

    Actor: The threat actor, or sometimes the general type of threat actor, you are looking for. Many things are not tied to a specific actor, so you won't always need to specify this part, but if you do, it can supply valuable context to help with the rest of your hunt.
    Behavior: The specific activity you're trying to find, sometimes called TTPs (Tactics, Techniques, and Procedures). Instead of hunting for an entire Kill Chain's worth of behavior, focus on one or two pieces at a time.
    Location: The part(s) of your organization's network where you would expect to find the behavior (e.g., end-user desktops or Internet-facing web servers). A proper location helps narrow the scope of your hunt, making it easier and more efficient.
    Evidence: A combination of which data source(s) you'd need to consult to find the activity and what it would look like if the activity were present. You'll need to know these when planning your data collection as well as when creating your analysis strategy.
    """

    prompt = f"""
    As a 25-year experienced Cybersecurity Threat Hunter, use the following context to create a hypothesis for a threat hunt based on a compiled threat report:

    {context}

    The threat report contains detailed information about recent incidents, threat actors, attack types, and indicators of compromise (IoCs). Please focus on these elements to construct a relevant threat hypothesis.

    Threat Report Content:
    {threat_report}

    Based on the above information, provide a detailed and relevant threat hypothesis that aligns with the content of the report.
    """

    window['-PROGRESS-'].update_bar(50)
    hypothesis = call_gpt([{"role": "user", "content": prompt}], config=config)
    window['-PROGRESS-'].update_bar(100)
    window['-STATUS-'].update('Hypothesis built.')
    return hypothesis

def build_rule(window, values, conversation_history, config):
    prompt = values['-PROMPT_INPUT-'].strip()
    if not prompt:
        sg.popup('Error', 'The prompt input is empty. Please enter a prompt before building the rule.')
        return conversation_history

    rule_types = []
    if values['-SIGMA-']:
        rule_types.append('Sigma')
    if values['-YARA-']:
        rule_types.append('Yara')
    if values['-SURICATA-']:
        rule_types.append('Suricata')
    if values['-KQL-']:
        rule_types.append('KQL')

    if not rule_types:
        sg.popup('Error', 'At least one rule type must be selected.')
        return conversation_history

    rule_types_str = ', '.join(rule_types)

    full_prompt = (
        "As an experienced cybersecurity analyst, create a detection rule based on the following information. "
        f"The rule should be in {rule_types_str}. "
        "Include comments explaining the rationale behind each part of the rule.\n\n"
        f"Information: {prompt}\n\n"
        "Please provide the rule in a clear, implementable format with explanatory comments."
    )

    conversation_history.append({"role": "user", "content": full_prompt})

    window['-STATUS-'].update('Generating detection rule...')
    window['-PROGRESS-'].update_bar(50)

    try:
        response = call_gpt(conversation_history, config=config)
        conversation_history.append({"role": "assistant", "content": response})
        window['-RULE_OUTPUT-'].update(response)
        window['-STATUS-'].update('Detection rule generated.')

    except Exception as e:
        sg.popup('An error occurred while generating the rule', str(e))
        window['-STATUS-'].update('Error occurred.')

    window['-PROGRESS-'].update_bar(100)
    return conversation_history

def analyze_pcap(window, values, config):
    if not config.api_key and not config.use_local_model:
        sg.popup('API key is not set!')
        return

    pcap_path = values['-PCAP_FILE_PATH-']
    include_alerts = values['-INCLUDE_ALERTS-']
    alerts_path = values['-ALERTS_FILE_PATH-'] if include_alerts else None

    if not pcap_path:
        sg.popup('Error', 'Please select a PCAP file.')
        return

    window['-STATUS-'].update('Analyzing PCAP...')
    window['-PROGRESS-'].update_bar(0)
    try:
        pcap_results = analyze_pcap_file(window, pcap_path, alerts_path, config)
        if pcap_results is None:
            window['-STATUS-'].update('PCAP analysis failed')
            window['-PROGRESS-'].update_bar(0)
            raise Exception("PCAP analysis failed")
        
        summarized_results = summarize_pcap_results(pcap_results)
        window['-PCAP_RESULTS-'].update(summarized_results)

        window['-STATUS-'].update('Generating AI analysis...')
        window['-PROGRESS-'].update_bar(75)

        prompt = (
            "Analyze the following summarized network traffic for anomalies or potential threats. "
            "Provide a detailed report that includes:\n\n"
            "1. **Unique URLs and Domain Names:**\n"
            "- Identify and list all unique URLs and domain names accessed within the network traffic.\n"
            "- Highlight any suspicious or potentially malicious domains that may indicate phishing or C2 activity.\n\n"
            "2. **File Analysis:**\n"
            "- List all files transferred over the network (both downloaded and uploaded), including their names, types, and associated hashes.\n"
            "- Pay special attention to executable files and other potentially harmful content for downloads.\n"
            "- For uploaded files, consider the potential for sensitive data exfiltration.\n"
            "- Associate file names with their corresponding hashes where possible.\n\n"
            "3. **Network Flow Relationships:**\n"
            "- Map out the network flow relationships, detailing the communication patterns between different IP addresses and ports.\n"
            "- Identify any unusual or unexpected traffic patterns that could suggest lateral movement or data exfiltration.\n\n"
            "4. **Indicators of Compromise (IoCs):**\n"
            "- Extract and list any IoCs found in the traffic, such as IP addresses, file hashes, or specific URLs associated with known threats.\n"
            "- Include file names associated with the hashes where available.\n\n"
            "5. **Threat Context and Recommendations:**\n"
            "- Provide context for the identified threats, including possible attack vectors and threat actor profiles.\n"
            "- Offer actionable recommendations for mitigating identified threats and improving network security posture.\n"
            "- Include specific recommendations for handling potentially sensitive data in uploaded files.\n\n"
            "Ensure the report is clear and concise, suitable for both technical SOC analysts and non-technical stakeholders. "
            "Use tables and charts where applicable to enhance readability and understanding.\n\n"
            f"Network Traffic Summary:\n{summarized_results}"
        )
        
        if include_alerts and alerts_path:
            alerts_data = read_file(alerts_path)
            prompt += (
                "\n\nAdditionally, consider the following alerts data from Network Detection systems. "
                "These alerts provide insights into potential security incidents and anomalies detected in the network. "
                "Please analyze these alerts in conjunction with the network traffic to identify correlations, "
                "validate potential threats, and assess the overall security posture:\n"
                f"{alerts_data}"
            )

        window['-STATUS-'].update('Generating AI analysis...')
        window['-PROGRESS-'].update_bar(90)
        pcap_analysis = call_gpt([{"role": "user", "content": prompt}], config=config)
        window['-PCAP_RESULTS-'].update('\n\n', append=True)
        window['-PCAP_RESULTS-'].update(pcap_analysis, append=True)

        window['-STATUS-'].update('Analysis complete.')
        window['-PROGRESS-'].update_bar(100)

        if values['-SAVE_PCAP_RESULTS-']:
            config.update(pcap_file_path=pcap_path, pcap_output=pcap_analysis, pcap_alerts_path=alerts_path)

        if values['-EXPORT_PCAP_RESULTS-']:
            window['-STATUS-'].update('Generating Word document...')
            window['-PROGRESS-'].update_bar(0)
            report_name = 'PCAP_Analysis_Report.docx'
            report_path = save_report(pcap_analysis, report_name)
            window['-PROGRESS-'].update_bar(100)
            response = sg.popup('Report Generated!', f'Report saved at: {report_path}', custom_text=('Open', 'Close'), keep_on_top=True)
            if response == 'Open':
                open_file(report_path)
            window['-STATUS-'].update('Done')
    except Exception as e:
        error_message = f"An error occurred during PCAP analysis: {str(e)}"
        sg.popup_error(error_message)
        window['-STATUS-'].update('Error occurred')
        window['-PROGRESS-'].update_bar(0)

def execute_command(window, values, command, config, local_only=False):
    try:
        full_response = []
        ai_only = values['-AI_ONLY-']
        first_chunk = True
        previous_type = None
        window['-PROGRESS-'].update_bar(50)

        print(f"Executing command: {command}")  # Debug
        
        try:
            if config.use_local_model and local_only:
                # For Local AI, only use the current command
                for chunk in interpreter.chat(command, stream=True, display=False):
                    if chunk["type"] in ["message", "console", "input"]:
                        if "content" in chunk and chunk["content"] is not None:
                            content = str(chunk["content"])
                            if ai_only and chunk["type"] != "message":
                                continue
                            if first_chunk:
                                content = content.lstrip('1').lstrip()
                                first_chunk = False
                            if previous_type and previous_type != chunk["type"]:
                                full_response.append('\n\n')
                            full_response.append(content)
                            previous_type = chunk["type"]
            else:
                # For OpenAI or when not using local_only, use the existing functionality
                for chunk in interpreter.chat(command, stream=True, display=False):
                    if chunk["type"] in ["message", "console", "input"]:
                        if "content" in chunk and chunk["content"] is not None:
                            content = str(chunk["content"])
                            if "Password:" in content:
                                password = sg.popup_get_text("Password required:", password_char='*')
                                if password:
                                    interpreter.chat(password, stream=False, display=False)
                                else:
                                    full_response.append("Password entry cancelled. Command execution aborted.")
                                    break
                            elif ai_only and chunk["type"] != "message":
                                continue
                            else:
                                if first_chunk:
                                    content = content.lstrip('1').lstrip()
                                    first_chunk = False
                                if previous_type and previous_type != chunk["type"]:
                                    full_response.append('\n\n')
                                full_response.append(content)
                                previous_type = chunk["type"]
        except interpreter.exceptions.APIConnectionError as e:
            error_message = f"Error connecting to the AI model: {str(e)}"
            full_response.append(error_message)
            full_response.append("Please ensure the AI model (local or remote) is running and accessible.")
        except Exception as e:
            error_message = f"An unexpected error occurred: {str(e)}"
            full_response.append(error_message)

        return ''.join(str(item) for item in full_response).strip()

    except Exception as e:
        error_message = f"Error executing command: {str(e)}"
        window['-STATUS-'].update(error_message)
        return error_message

def analyze_pcap_file(window, pcap_path, alerts_path=None, config=None):
    window['-STATUS-'].update('Reading PCAP file...')
    window['-PROGRESS-'].update_bar(20)
    packets = read_pcap_file(pcap_path)

    window['-STATUS-'].update('Summarizing traffic...')
    window['-PROGRESS-'].update_bar(40)
    pcap_summary = summarize_traffic(packets)

    window['-STATUS-'].update('Extracting files and hashes...')
    window['-PROGRESS-'].update_bar(60)
    file_hashes = extract_files_and_calculate_hashes(pcap_path)
    file_hashes_str = "\n".join([f"{protocol}: {file_hash} ({file_name})" for protocol, file_hash, file_name in file_hashes])

    window['-STATUS-'].update('Compiling analysis results...')
    window['-PROGRESS-'].update_bar(80)
    analysis_result = f"{pcap_summary}\n\nFile Hashes (IoCs):\n{file_hashes_str}"

    window['-STATUS-'].update('PCAP analysis complete.')
    window['-PROGRESS-'].update_bar(100)

    return analysis_result

def extract_files_and_calculate_hashes(pcap_file):
    file_hashes = []
    
    cap = pyshark.FileCapture(pcap_file, display_filter="http or smtp or ftp-data or smb2")
    
    for packet in cap:
        try:
            file_content = None
            file_name = None
            protocol = None

            if 'HTTP' in packet:
                if hasattr(packet.http, 'file_data'):
                    file_content = packet.http.file_data.binary_value
                    protocol = "HTTP"
                    
                    # Try to get the file name from Content-Disposition header
                    if hasattr(packet.http, 'content_disposition'):
                        content_disp = packet.http.content_disposition
                        if 'filename=' in content_disp:
                            file_name = content_disp.split('filename=')[-1].strip('"')
                    
                    # If file name not found in Content-Disposition, try to get it from the URL
                    if not file_name and hasattr(packet.http, 'request_uri'):
                        url_path = unquote(packet.http.request_uri)
                        file_name = os.path.basename(url_path)
                    
                    # If still no file name, use the default
                    if not file_name:
                        file_name = f"http_file_{packet.number}"
            elif 'SMTP' in packet:
                if hasattr(packet.smtp, 'data_fragment'):
                    file_content = packet.smtp.data_fragment.binary_value
                    file_name = f"smtp_file_{packet.number}"
                    protocol = "SMTP"
            elif 'FTP_DATA' in packet:
                if hasattr(packet.ftp_data, 'data'):
                    file_content = packet.ftp_data.data.binary_value
                    file_name = f"ftp_file_{packet.number}"
                    protocol = "FTP"
            elif 'SMB2' in packet:
                if hasattr(packet.smb2, 'file_data'):
                    file_content = packet.smb2.file_data.binary_value
                    file_name = f"smb_file_{packet.number}"
                    protocol = "SMB"

            if file_content and file_name and protocol:
                file_hash = hashlib.sha256(file_content).hexdigest()
                file_hashes.append((protocol, file_hash, file_name))
            
        except AttributeError as e:
            print(f"AttributeError processing packet {packet.number}: {e}")
        except ValueError as e:
            print(f"ValueError processing packet {packet.number}: {e}")
        except Exception as e:
            print(f"Error processing packet {packet.number}: {e}")
    
    return file_hashes

def summarize_traffic(packets):
    ip_summary = {}
    port_summary = {}
    protocol_summary = {}
    http_payloads = []
    dns_queries = []
    smtp_payloads = []
    ftp_payloads = []
    smb_operations = []
    executable_downloads = []
      
    for packet in packets:
        if packet.haslayer(IP):
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            ip_summary[f"{ip_src} to {ip_dst}"] = ip_summary.get(f"{ip_src} to {ip_dst}", 0) + 1

        if packet.haslayer(TCP):
            port_summary[packet[TCP].sport] = port_summary.get(packet[TCP].sport, 0) + 1

        if packet.haslayer(IP):
            protocol_summary[packet[IP].proto] = protocol_summary.get(packet[IP].proto, 0) + 1

        # Extract HTTP payloads and detect executables
        if packet.haslayer(HTTPRequest) or packet.haslayer(HTTPResponse):
            if packet.haslayer(Raw):
                raw_data = packet[Raw].load
                try:
                    if b"Content-Type: text" in raw_data:
                        payload = raw_data.decode('utf-8', errors='replace')
                        http_payloads.append(payload)
                    elif is_executable(raw_data):
                        executable_downloads.append("<Executable file detected>")
                    else:
                        # Attempt alternative decoding strategies
                        payload = raw_data.decode('iso-8859-1', errors='replace')
                        http_payloads.append(payload)
                except Exception as e:
                    http_payloads.append(f"<Error processing HTTP payload: {e}>")

        # Extract DNS queries
        if packet.haslayer(DNS) and packet.haslayer(DNSQR):
            try:
                dns_query = packet[DNSQR].qname.decode('utf-8', errors='replace')
                dns_queries.append(dns_query)
            except Exception as e:
                dns_queries.append(f"<Error decoding DNS query: {e}>")

        # Extract SMTP payloads
        if packet.haslayer(TCP) and packet[TCP].dport == 25:  # SMTP typically uses port 25
            if packet.haslayer(Raw):
                try:
                    payload = packet[Raw].load.decode('utf-8', errors='replace')
                    smtp_payloads.append(payload)
                except Exception as e:
                    smtp_payloads.append(f"<Error decoding SMTP payload: {e}>")

        # Extract FTP payloads
        if packet.haslayer(TCP) and (packet[TCP].dport == 21 or packet[TCP].sport == 21):  # FTP uses port 21
            if packet.haslayer(Raw):
                try:
                    payload = packet[Raw].load.decode('utf-8', errors='replace')
                    ftp_payloads.append(payload)
                except Exception as e:
                    ftp_payloads.append(f"<Error decoding FTP payload: {e}>")

        # Analyze SMB traffic
        if packet.haslayer(TCP) and (packet[TCP].dport == 445 or packet[TCP].sport == 445):
            if packet.haslayer(NBTSession):
                try:
                    smb_layer = packet[NBTSession].payload
                    if hasattr(smb_layer, 'Command'):
                        command = smb_layer.Command
                        smb_operations.append(f"SMB Command: {command}")
                    elif hasattr(smb_layer, 'Flags2') and hasattr(smb_layer, 'Flags'):
                        flags = f"Flags: {smb_layer.Flags}, Flags2: {smb_layer.Flags2}"
                        smb_operations.append(f"SMB Flags: {flags}")
                except Exception as e:
                    smb_operations.append(f"<Error analyzing SMB packet: {e}>")

    ip_summary_str = "\n".join(f"{k}: {v} packets" for k, v in ip_summary.items())
    port_summary_str = "\n".join(f"Port {k}: {v} packets" for k, v in port_summary.items())
    protocol_summary_str = "\n".join(f"Protocol {k}: {v} packets" for k, v in protocol_summary.items())
    http_payloads_str = "\n\n".join(http_payloads)
    dns_queries_str = "\n".join(dns_queries)
    smtp_payloads_str = "\n\n".join(smtp_payloads)
    ftp_payloads_str = "\n\n".join(ftp_payloads)
    smb_operations_str = "\n".join(smb_operations)
    executable_downloads_str = "\n".join(executable_downloads)
    
    return (f"IP Summary:\n{ip_summary_str}\n\n"
            f"Port Summary:\n{port_summary_str}\n\n"
            f"Protocol Summary:\n{protocol_summary_str}\n\n"
            f"HTTP Payloads:\n{http_payloads_str}\n\n"
            f"DNS Queries:\n{dns_queries_str}\n\n"
            f"SMTP Payloads:\n{smtp_payloads_str}\n\n"
            f"FTP Payloads:\n{ftp_payloads_str}\n\n"
            f"SMB Operations:\n{smb_operations_str}\n\n"
            f"Executable Downloads:\n{executable_downloads_str}")

def read_pcap_file(pcap_path):
    return rdpcap(pcap_path)

def summarize_pcap_results(pcap_results, max_length=10000, max_total_chars=400000):
    sections = pcap_results.split('\n\n')
    summarized_sections = []
    total_chars = 0
    
    for section in sections:
        if len(section) > max_length:
            truncated_section = section[:max_length] + f"\n...(truncated, full length: {len(section)} characters)"
            summarized_sections.append(truncated_section)
            total_chars += len(truncated_section)
        else:
            summarized_sections.append(section)
            total_chars += len(section)
        
        if total_chars > max_total_chars:
            summarized_sections.append(f"\n\nAnalysis truncated due to length. Total sections: {len(sections)}, Included sections: {len(summarized_sections)}")
            break
    
    return '\n\n'.join(summarized_sections)
            