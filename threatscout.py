import os
import re
import sys
import json
import subprocess
from cryptography.fernet import Fernet, InvalidToken
import openai
import PySimpleGUI as sg
import hashlib
from scapy.all import rdpcap, IP, TCP, UDP, Raw
from scapy.layers.http import HTTPRequest, HTTPResponse
from scapy.layers.dns import DNS, DNSQR
import pypandoc
from docx import Document
import PyPDF2
from interpreter import interpreter

THREATSCOUT_VERSION = 'ThreatScout version 0.5'
CONFIG_FILE = 'config.json'
KEY_FILE = 'key.key'

# Path to ThreatScout logo images
logo_image_path = 'Images/Docrop2.png'
text_image_path = 'Images/big_ThreatScout.png'

def generate_key():
    key = Fernet.generate_key()
    with open(KEY_FILE, 'wb') as key_file:
        key_file.write(key)
    return key

def load_key():
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, 'rb') as key_file:
            return key_file.read()
    return generate_key()

encryption_key = load_key()
cipher_suite = Fernet(encryption_key)

def encrypt_api_key(api_key):
    return cipher_suite.encrypt(api_key.encode()).decode()

def decrypt_api_key(encrypted_api_key):
    try:
        return cipher_suite.decrypt(encrypted_api_key.encode()).decode()
    except (InvalidToken, AttributeError):
        sg.popup('Error', 'Failed to decrypt the API key. Please re-enter your API key.')
        return None

def save_config(api_key=None, theme=None, analyze_file_path=None, analyze_output=None,
                hypothesis_file_path=None, hypothesis_output=None, pcap_file_path=None,
                pcap_output=None, pcap_alerts_path=None, rule_output=None, prompt_input=None):
    config = {}
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, 'r') as config_file:
            config = json.load(config_file)

    if api_key:
        config['ENCRYPTED_OPENAI_API_KEY'] = encrypt_api_key(api_key)
    if theme:
        config['THEME'] = theme
    if analyze_file_path is not None:
        config['ANALYZE_FILE_PATH'] = analyze_file_path
    if analyze_output is not None:
        config['ANALYZE_OUTPUT'] = analyze_output
    if hypothesis_file_path is not None:
        config['HYPOTHESIS_FILE_PATH'] = hypothesis_file_path
    if hypothesis_output is not None:
        config['HYPOTHESIS_OUTPUT'] = hypothesis_output
    if pcap_file_path is not None:
        config['PCAP_FILE_PATH'] = pcap_file_path
    if pcap_output is not None:
        config['PCAP_OUTPUT'] = pcap_output
    if pcap_alerts_path is not None:
        config['PCAP_ALERTS_PATH'] = pcap_alerts_path
    if rule_output is not None:
        config['RULE_OUTPUT'] = rule_output
    if prompt_input is not None:
        config['PROMPT_INPUT'] = prompt_input

    with open(CONFIG_FILE, 'w') as config_file:
        json.dump(config, config_file)

def load_config():
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, 'r') as config_file:
            config = json.load(config_file)

        encrypted_api_key = config.get('ENCRYPTED_OPENAI_API_KEY')
        theme = config.get('THEME', 'DarkGrey16')
        analyze_file_path = config.get('ANALYZE_FILE_PATH', '')
        analyze_output = config.get('ANALYZE_OUTPUT', '')
        hypothesis_file_path = config.get('HYPOTHESIS_FILE_PATH', '')
        hypothesis_output = config.get('HYPOTHESIS_OUTPUT', '')
        pcap_file_path = config.get('PCAP_FILE_PATH', '')
        pcap_output = config.get('PCAP_OUTPUT', '')
        pcap_alerts_path = config.get('PCAP_ALERTS_PATH', '')
        rule_output = config.get('RULE_OUTPUT', '')
        prompt_input = config.get('PROMPT_INPUT', '')

        if encrypted_api_key:
            return (decrypt_api_key(encrypted_api_key), theme, analyze_file_path, analyze_output,
                    hypothesis_file_path, hypothesis_output, pcap_file_path, pcap_output,
                    pcap_alerts_path, rule_output, prompt_input)

    return None, 'DarkGrey16', '', '', '', '', '', '', '', '', ''

def call_gpt(client, prompt, history=None):
    if not history:
        messages = [
            {'role': 'system', 'content': 'You are a cybersecurity SOC analyst with more than 25 years of experience.'},
            {'role': 'user', 'content': prompt}
    ]
    else:
        messages = prompt

    response = client.chat.completions.create(
        model='gpt-4o',
        messages=messages,
        max_tokens=2048,
        n=1,
        stop=None,
        temperature=0.7
    )
    return response.choices[0].message.content.strip()

def read_docx(file_path):
    doc = Document(file_path)
    full_text = []
    for para in doc.paragraphs:
        full_text.append(para.text)
    return '\n'.join(full_text)

def read_pdf(file_path):
    with open(file_path, 'rb') as file:
        reader = PyPDF2.PdfReader(file)
        full_text = []
        for page in reader.pages:
            full_text.append(page.extract_text())
    return '\n'.join(full_text)

def read_file(file_path):
    if file_path.endswith('.docx'):
        return read_docx(file_path)
    elif file_path.endswith('.pdf'):
        return read_pdf(file_path)
    else:
        with open(file_path, 'r') as file:
            return file.read()

def analyze_threat_data(client, file_path, window):
    try:
        raw_data = read_file(file_path)
    except FileNotFoundError:
        sg.popup('Error', 'No file selected or file not found. Please select a valid threat data file.')
        return None, None, None

    window['-PROGRESS-'].update_bar(0)
    window['-STATUS-'].update('Analyzing threats...')
    identified_threats = call_gpt(client, f'Analyze the following threat data and identify potential threats: {raw_data}')
    window['-PROGRESS-'].update_bar(33)
    window['-STATUS-'].update('Extracting IOCs...')
    extracted_iocs = call_gpt(client, f'''Extract all indicators of compromise (IoCs) and Tactics, Techniques and Procedures (TTPs)
    from the following threat data and create a table with the results.
    Please ensure that all tables in the document are formatted to fit their content optimally: {raw_data}''')
    window['-PROGRESS-'].update_bar(66)
    window['-STATUS-'].update('Providing threat context...')
    threat_context = call_gpt(client, f'Provide a detailed context or narrative behind the identified threats in this data: {raw_data}')
    window['-PROGRESS-'].update_bar(100)
    window['-STATUS-'].update('Analysis complete.')
    return identified_threats, extracted_iocs, threat_context

def markdown_to_docx(markdown_text: str, output_file: str) -> bool:
    """Convert markdown text to a .docx file."""
    try:
        pypandoc.convert_text(markdown_text, 'docx', format='md', outputfile=output_file)
        return True
    except RuntimeError as e:
        print(f"Error during conversion: {e}")
        return False

def save_report(output, report_name):
    if not os.path.exists('Reports'):
        os.makedirs('Reports')
    
    base_name, extension = os.path.splitext(report_name)
    index = 1
    report_path = os.path.join('Reports', report_name)
    while os.path.exists(report_path):
        report_name = f"{base_name}_{index}{extension}"
        report_path = os.path.join('Reports', report_name)
        index += 1
    
    if markdown_to_docx(output, report_path):
        return report_path
    else:
        return None

def save_to_file(content, base_name, extension):
    """Save content to a file, ensuring the filename is unique."""
    if not os.path.exists('Sessions'):
        os.makedirs('Sessions')
    index = 1
    file_name = f"{base_name}{extension}"
    while os.path.exists(os.path.join('Sessions', file_name)):
        file_name = f"{base_name}_{index}{extension}"
        index += 1
    with open(os.path.join('Sessions', file_name), 'w') as file:
        file.write(content)
    return file_name

def calculate_file_hash(file_data, hash_algorithm='sha256'):
    #--- Calculate the hash of file data using the specified algorithm. ---
    hash_obj = hashlib.new(hash_algorithm)
    hash_obj.update(file_data)
    return hash_obj.hexdigest()

def extract_files_and_calculate_hashes(packets):
    #--- Extract files from packets and calculate their hashes. ---
    file_hashes = []

    for packet in packets:
        if packet.haslayer(TCP) and packet.haslayer(Raw):
            # Example: Extract HTTP payloads as files
            if packet.haslayer(HTTPRequest) or packet.haslayer(HTTPResponse):
                raw_data = packet[Raw].load
                try:
                    # Look for content-type headers indicating file content
                    if b"Content-Type: application" in raw_data or b".exe" in raw_data:
                        # Calculate hash for the file content
                        file_hash = calculate_file_hash(raw_data)
                        file_hashes.append(file_hash)
                except Exception as e:
                    print(f"Error processing packet: {e}")

    return file_hashes

def read_pcap_file(pcap_path):
    return rdpcap(pcap_path)

def summarize_traffic(packets):
    ip_summary = {}
    port_summary = {}
    protocol_summary = {}
    http_payloads = []
    dns_queries = []
    smtp_payloads = []
    ftp_payloads = []
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
                    # Check for common content types
                    if b"Content-Type: text" in raw_data:
                        payload = raw_data.decode('utf-8', errors='replace')
                        http_payloads.append(payload)
                    elif b"Content-Type: application/octet-stream" in raw_data or b".exe" in raw_data:
                        executable_downloads.append("<Binary data detected, not decoded>")
                    else:
                        # Attempt alternative decoding strategies
                        payload = raw_data.decode('iso-8859-1', errors='replace')
                        http_payloads.append(payload)
                except Exception as e:
                    http_payloads.append(f"<Error decoding HTTP payload: {e}>")

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

    ip_summary_str = "\n".join(f"{k}: {v} packets" for k, v in ip_summary.items())
    port_summary_str = "\n".join(f"Port {k}: {v} packets" for k, v in port_summary.items())
    protocol_summary_str = "\n".join(f"Protocol {k}: {v} packets" for k, v in protocol_summary.items())
    http_payloads_str = "\n\n".join(http_payloads)
    dns_queries_str = "\n".join(dns_queries)
    smtp_payloads_str = "\n\n".join(smtp_payloads)
    ftp_payloads_str = "\n\n".join(ftp_payloads)
    executable_downloads_str = "\n".join(executable_downloads)

    # Calculate file hashes
    file_hashes = extract_files_and_calculate_hashes(packets)
    file_hashes_str = "\n".join(file_hashes)

    return (f"IP Summary:\n{ip_summary_str}\n\n"
            f"Port Summary:\n{port_summary_str}\n\n"
            f"Protocol Summary:\n{protocol_summary_str}\n\n"
            f"HTTP Payloads:\n{http_payloads_str}\n\n"
            f"DNS Queries:\n{dns_queries_str}\n\n"
            f"SMTP Payloads:\n{smtp_payloads_str}\n\n"
            f"FTP Payloads:\n{ftp_payloads_str}\n\n"
            f"Executable Downloads:\n{executable_downloads_str}\n\n"
            f"File Hashes (IoCs):\n{file_hashes_str}")

def analyze_pcap_file(window, pcap_path, alerts_path=None):
    window['-STATUS-'].update('Reading PCAP file...')
    window['-PROGRESS-'].update_bar(25)
    packets = read_pcap_file(pcap_path)

    window['-STATUS-'].update('Summarizing traffic...')
    window['-PROGRESS-'].update_bar(50)
    pcap_summary = summarize_traffic(packets)

    return pcap_summary

def execute_command(window, command, ai_only=False):
    try:
        full_response = []
        first_chunk = True
        previous_type = None
        password_prompt = False
        
        window['-PROGRESS-'].update_bar(50)
        for chunk in interpreter.chat(command, stream=True, display=False):
            if chunk["type"] in ["message", "console", "input"]:
                if "content" in chunk and chunk["content"] is not None:
                    content = str(chunk["content"])
                    
                    # Filter out console responses if the checkbox is checked
                    if ai_only and chunk["type"] != "message":
                        continue
                    
                    if first_chunk:
                        content = content.lstrip('1').lstrip()
                        first_chunk = False
                    
                    # Add a newline if the type changes
                    if previous_type and previous_type != chunk["type"]:
                        full_response.append('\n\n')
                    
                    full_response.append(content)
                    previous_type = chunk["type"]
                    
                    # Check for password prompt
                    if any(keyword in content.lower() for keyword in ["Password:", "sudo", "authentication"]):
                        password_prompt = True
                        break  # Exit the loop if a password prompt is detected
        
        if password_prompt:
            return "Password prompt detected. Unable to proceed automatically."
        else:
            return ''.join(full_response).strip()
    except Exception as e:
        return f"Error executing command: {str(e)}"
    
def create_detection_rule_builder_tab():
    default_prompt_text = (
        "How to Build and Refine Detection Rules:\n\n"
        "1. Identify Unique Threats: Conduct assessments to identify specific threats.\n"
        "2. Draft Rules with AI: Use specific threat characteristics in your prompts.\n"
        "3. Test Rules: Deploy in a test environment and check for false positives.\n"
        "4. Refinement: Come back here and use the test results to refine rules.\n"
        "5. Deployment: Deploy refined rules into production systems.\n\n"
        "Note: Once you exit or close this program, the AI conversation history is lost."
    )
    
    return sg.Tab('Detection Rule Builder', [
        [sg.HorizontalSeparator()],
        [sg.Text('Prompt Input:')],
        [sg.Multiline(default_text=default_prompt_text, size=(124, 10), key='-PROMPT_INPUT-', expand_x=True, expand_y=True, 
                      font=('Helvetica', 12, 'italic'))],  # Multiline with default text and italic font
        [sg.Text('Rule Options:')],
        [sg.Checkbox('Sigma', key='-SIGMA-'), sg.Checkbox('Yara', key='-YARA-'), sg.Checkbox('Suricata', key='-SURICATA-'), sg.Checkbox('KQL', key='-KQL-')],
        [sg.HorizontalSeparator()],
        [sg.Frame('Rule Output', [
            [sg.Multiline(size=(124, 10), key='-RULE_OUTPUT-', expand_x=True, expand_y=True)]
        ], expand_x=True, expand_y=True)],
        [sg.HorizontalSeparator()],
        [sg.Column([
            [sg.Button('Build', key='-BUILD_RULE-', size=(10, 1)), sg.Button('Clear', key='-CLEAR_RULE-', size=(10, 1)), sg.Push(), sg.Text('Options:'), 
             sg.Checkbox('Save I/O', key='-SAVE_RULE-'), sg.Checkbox('Export Rule', key='-EXPORT_RULE-')]
        ], element_justification='center', expand_x=True)],
    ], key='-DETECTION_RULE_BUILDER_TAB-')

def create_threat_hunt_local_shell_tab():
    return sg.Tab('Local Shell', [
        [sg.HorizontalSeparator()],
        [sg.Text('Threat Hunt Prompt:')],
        [sg.Input(size=(124, 0), key='-SHELL_PROMPT_INPUT-', expand_x=True, disabled=True,  font=('Helvetica', 12, 'italic'))],  # Initially disabled
        [sg.Text('Shell Options:')],
        [sg.Checkbox('Save session to file', key='-SAVE_SHELL_SESSION-'), 
         sg.Checkbox('No console output', key='-AI_ONLY-', default=True)],
        [sg.HorizontalSeparator()],
        [sg.Frame('Shell Output', [
            [sg.Multiline(size=(124, 10), key='-SHELL_OUTPUT-', expand_x=True, expand_y=True, disabled=True)]
        ], expand_x=True, expand_y=True)],
        [sg.HorizontalSeparator()],
        [sg.Column([
            [sg.Button('Start', key='-START_SHELL-', size=(10, 1)),  # Start button
             sg.Button('Send', key='-SEND_SHELL-', size=(10, 1), disabled=True),  # Initially disabled
             sg.Button('Clear', key='-CLEAR_SHELL-', size=(10, 1)),
             sg.Button('Done', key='-DONE_SHELL-', size=(10, 1)),  # Done button
             sg.Push(), sg.Text('Option:'),
             sg.Checkbox('Export Session', key='-EXPORT_SHELL_SESSION-')]
        ], element_justification='center', expand_x=True)],
    ], key='-THREAT_HUNT_LOCAL_SHELL_TAB-')

def create_gui_layout():
    layout = [
        [sg.Image(filename=text_image_path, key='-THREATSCOUT-TXT-IMAGE-'), sg.Text('Threat Hunt Assist Tool'),
         sg.Push(),  # This will push the next elements to the far right
         sg.Image(filename=logo_image_path, key='-THREATSCOUTLOGO-IMAGE-', pad=((0, 0), (10, 0)))],
        [sg.Menu([['File', ['Exit']], ['Settings', ['API Key', 'Theme']], ['Help', ['About']]])],
        [sg.TabGroup([[
            sg.Tab('Threat Report Analyzer', [
                [sg.HorizontalSeparator()],
                [sg.Text('Threat Data Path:'), sg.InputText(key='-FILE_PATH-', expand_x=True), sg.FileBrowse()],
                [sg.HorizontalSeparator()],
                [sg.Frame('Threat Analysis', [
                    [sg.Multiline(size=(124, 20), key='-OUTPUT-', disabled=True, expand_x=True, expand_y=True)]
                ], expand_x=True, expand_y=True)],
                [sg.HorizontalSeparator()],
                [sg.Column([
                    [sg.Button('Analyze', size=(10, 1)), sg.Button('Clear', size=(10, 1)), sg.Push(), sg.Text('Options:'), sg.Checkbox('Save I/O', key='-SAVE-'), sg.Checkbox('Export Report', key='-EXPORT-')]
                ], element_justification='center', expand_x=True)]
            ], key='-ANALYZE_TAB-'),
            sg.Tab('Hypothesis Builder', [
                [sg.HorizontalSeparator()],
                [sg.Text('Threat Report Path:'), sg.InputText(key='-THREAT_REPORT_FILE_PATH-', expand_x=True), sg.FileBrowse()],
                [sg.HorizontalSeparator()],
                [sg.Frame('Threat Hypothesis', [
                    [sg.Multiline(size=(124, 10), key='-THREAT_HYPOTHESIS-', expand_x=True, expand_y=True)]
                ], expand_x=True, expand_y=True)],
                [sg.HorizontalSeparator()],
                [sg.Column([
                    [sg.Button('Build', key='-BUILD_HYPOTHESIS-', size=(10, 1)), sg.Button('Clear', key='-CLEAR_HYPOTHESIS-', size=(10, 1)), sg.Push(), sg.Text('Options:'), sg.Checkbox('Save I/O', key='-SAVE_HYPOTHESIS-'), sg.Checkbox('Export Report', key='-EXPORT_HYPOTHESIS-')]
                ], element_justification='center', expand_x=True)],
            ], key='-HYPOTHESIS_TAB-'),
            sg.Tab('PCAP Analyzer', [
                [sg.HorizontalSeparator()],
                [sg.Text('PCAP Path:'), sg.InputText(key='-PCAP_FILE_PATH-', expand_x=True), sg.FileBrowse()],
                [sg.Checkbox('Include Alerts', key='-INCLUDE_ALERTS-', default=False, enable_events=True)], # I had to add enable_events=True to trigger this event
                [sg.Text('Alerts Path:'), sg.InputText(key='-ALERTS_FILE_PATH-', expand_x=True, disabled=True), sg.FileBrowse(key='-ALERTS_FILE_BROWSE-', disabled=True)],
                [sg.HorizontalSeparator()],
                [sg.Frame('PCAP Analysis', [
                    [sg.Multiline(size=(124, 10), key='-PCAP_RESULTS-', expand_x=True, expand_y=True)]
                ], expand_x=True, expand_y=True)],
                [sg.HorizontalSeparator()],
                [sg.Column([
                    [sg.Button('Analyze', key='-ANALYZE_PCAP-', size=(10, 1)), sg.Button('Clear', key='-CLEAR_PCAP_RESULTS-', size=(10, 1)), sg.Push(), sg.Text('Options:'), sg.Checkbox('Save I/O', key='-SAVE_PCAP_RESULTS-'), sg.Checkbox('Export Report', key='-EXPORT_PCAP_RESULTS-')]
                ], element_justification='center', expand_x=True)],
            ], key='-PCAP_TAB-')],
             [create_detection_rule_builder_tab()],  # New tab
             [create_threat_hunt_local_shell_tab()]  # New tab
            ], expand_x=True, expand_y=True)],
        [sg.HorizontalSeparator()],
        [sg.Text(THREATSCOUT_VERSION + ' :: ' + 'Powered by AI'), sg.Push(), sg.Text('Progress:'), sg.ProgressBar(100, orientation='h', size=(15, 20), key='-PROGRESS-'), sg.VerticalSeparator(), sg.Text('Status:'), sg.Text('- Ready -', size=(25, 1), key='-STATUS-', justification='right')]
    ]
    return layout

def api_key_window(api_key):
    layout = [
        [sg.Text('API Key:'), sg.InputText(api_key, key='-API_KEY-', password_char='*')],
        [sg.Button('Save API Key')]
    ]
    return sg.Window('API Key Settings', layout)

def theme_window(current_theme):
    themes = sg.theme_list()
    layout = [
        [sg.Text('Select Theme:'), sg.Combo(themes, default_value=current_theme, key='-THEME-', readonly=True)],
        [sg.Button('Save Theme')]
    ]
    return sg.Window('Theme Settings', layout)

def build_threat_hypothesis(client, file_path, window):
    try:
        threat_report = read_file(file_path)
    except FileNotFoundError:
        sg.popup('Error', 'No file selected or file not found. Please select a valid threat report file.')
        return None

    window['-STATUS-'].update('Building threat hypothesis...')
    window['-PROGRESS-'].update_bar(0)

    context = """
    Hypothesis-based hunts rely on a central hunch or educated guess that guides your investigation. These hypotheses are based on a combination of a hunter’s intuition, experience and research. Crafting a solid hunting hypothesis requires a delicate blend of creativity and analytical thinking.

    There are three steps to creating a good hypothesis:
    1. Select a topic: Identify a specific behavior of concern. Draw on your understanding of the threat landscape, recent incidents and emerging trends to pinpoint potential risks inside your network. Research some of the priority threat actors targeting your organization or your industry to identify their typical behaviors. However you go about it, the first step is to figure out what type of activity you want to look for.

    2. Make it testable: Write the topic as a statement or assertion that can be either proved or disproved. A hypothesis that can be disproved is said to be falsifiable. If the hypothesis is not falsifiable, it is not a valid hypothesis.

    3. Refine as necessary: Restate and rescope your hypothesis until it is falsifiable and you are certain that you can hunt it, given your timeframe and the resources available to you. Don’t be surprised if you need to refine your hypothesis even during the middle of the hunt.

    Are You ABLE to Hunt?
    Even though you now have a clear and testable hypothesis, you still need to know a few things before you can start hunting, such as possible indicators of the activity, data source(s) you need to examine, and in which parts of the network you might expect to observe it.

    PEAK incorporates the ABLE framework to help you capture the critical pieces of your hunting hypothesis:

    Actor: The threat actor, or sometimes the general type of threat actor, you are looking for. Many things are not tied to a specific actor, so you won’t always need to specify this part, but if you do, it can supply valuable context to help with the rest of your hunt.
    Behavior: The specific activity you’re trying to find, sometimes called TTPs (Tactics, Techniques, and Procedures). Instead of hunting for an entire Kill Chain’s worth of behavior, focus on one or two pieces at a time.
    Location: The part(s) of your organization’s network where you would expect to find the behavior (e.g., end-user desktops or Internet-facing web servers). A proper location helps narrow the scope of your hunt, making it easier and more efficient.
    Evidence: A combination of which data source(s) you’d need to consult to find the activity and what it would look like if the activity were present. You’ll need to know these when planning your data collection as well as when creating your analysis strategy.
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
    hypothesis = call_gpt(client, prompt)
    window['-THREAT_HYPOTHESIS-'].update(hypothesis)
    window['-PROGRESS-'].update_bar(100)
    window['-STATUS-'].update('Hypothesis built.')

def build_rule(client, window, values, conversation_history):
    # Retrieve user's prompt input
    user_prompt = values['-PROMPT_INPUT-'].strip()
    
    # Check which rule options are selected
    selected_rules = []
    if values['-SIGMA-']:
        selected_rules.append('Sigma')
    if values['-YARA-']:
        selected_rules.append('Yara')
    if values['-SURICATA-']:
        selected_rules.append('Suricata')
    if values['-KQL-']:
        selected_rules.append('KQL')
    
    # Ensure at least one rule is selected
    if not selected_rules:
        sg.popup('Error', 'At least one rule must be selected to build the rule.')
        return
    
    # Update status and progress
    window['-STATUS-'].update('Building rule...')
    window['-PROGRESS-'].update_bar(0)
    
    # Create the static prompt with placeholders
    rules = ', '.join(selected_rules)
    static_prompt = f"Can you help me draft a {rules} rule to detect this specific activity?"
    
    # Combine the user's prompt with the static prompt
    full_prompt = f"{user_prompt}\n\n{static_prompt}"
    
    # Add the user's input to the conversation history
    conversation_history.append({'role': 'user', 'content': full_prompt})
    
    # Call the OpenAI API with the conversation history
    try:
        window['-PROGRESS-'].update_bar(50)
        rule_output = call_gpt(client, conversation_history, history=True)
        conversation_history.append({'role': 'assistant', 'content': rule_output})
        window['-RULE_OUTPUT-'].update(rule_output)
        window['-STATUS-'].update('Rule built successfully.')
    except Exception as e:
        sg.popup('An error occurred while generating the rule', str(e))
        window['-STATUS-'].update('Error occurred.')
    
    # Update progress to complete
    window['-PROGRESS-'].update_bar(100)

    return conversation_history

def main():
    (api_key, theme, analyze_file_path, analyze_output, hypothesis_file_path, hypothesis_output,
     pcap_file_path, pcap_output, pcap_alerts_path, rule_output, prompt_input) = load_config()
    

    sg.theme(theme)
    sg.set_options(font=('Helvetica', 12))
    layout = create_gui_layout()
    window = sg.Window('.:: ThreatScout ::.', layout, size=(805, 625), resizable=True, finalize=True)
    client = openai.OpenAI(api_key=api_key) if api_key else None

    if analyze_file_path:
        window['-FILE_PATH-'].update(analyze_file_path)
    if analyze_output:
        window['-OUTPUT-'].update(analyze_output)
    if hypothesis_file_path:
        window['-THREAT_REPORT_FILE_PATH-'].update(hypothesis_file_path)
    if hypothesis_output:
        window['-THREAT_HYPOTHESIS-'].update(hypothesis_output)
    if pcap_file_path:
        window['-PCAP_FILE_PATH-'].update(pcap_file_path)
    if pcap_output:
        window['-PCAP_RESULTS-'].update(pcap_output)
    if pcap_alerts_path:
        window['-ALERTS_FILE_PATH-'].update(pcap_alerts_path)
    if rule_output:
        window['-RULE_OUTPUT-'].update(rule_output)
    if prompt_input:
        window['-PROMPT_INPUT-'].update(prompt_input)

    # Initialize conversation history
    conversation_history = [{'role': 'system', 'content': 'You are a cybersecurity SOC analyst with more than 25 years of experience.'}]

   # Configure the interpreter
    interpreter.model = "gpt-4o"
    interpreter.llm.api_key = api_key
    interpreter.llm.max_tokens = 1000
    interpreter.llm.context_window = 3000
    interpreter.auto_run = True
    interpreter.llm.supports_functions = True

    # Set custom system message
    interpreter.system_message = """
    Enable advanced security checks.
    Increase verbosity for system logs.
    Prioritize threat hunting commands.
    """

    # Bind the Enter key to the "Send" button
    window.bind('<Return>', '-SEND_SHELL-')

    # Initialize a flag to track if the event has been triggered before
    first_send_shell = True


    while True:
        event, values = window.read()
        print(f"Event: {event}")  # Debugging statement

        if event in (sg.WINDOW_CLOSED, 'Exit'):
            if event in (sg.WINDOW_CLOSED, 'Exit'):
                break

        elif event == 'Analyze':
            if client is None:
                sg.popup('API key is not set!')
                continue
            file_path = values['-FILE_PATH-']
            if not file_path:
                sg.popup('Error', 'No file selected. Please select a threat data file.')
                continue
            window['-STATUS-'].update('Starting analysis...')
            try:
                identified_threats, extracted_iocs, threat_context = analyze_threat_data(client, file_path, window)
                if identified_threats and extracted_iocs and threat_context:
                    output = f'Identified Threats:\n{identified_threats}\n\nExtracted IoCs:\n{extracted_iocs}\n\nThreat Context:\n{threat_context}'
                    window['-OUTPUT-'].update(output)
                    window['-STATUS-'].update('Done')
                    if values['-SAVE-']:
                        save_config(analyze_file_path=file_path, analyze_output=output)
                    if values['-EXPORT-']:
                        window['-STATUS-'].update('Generating Word document...')
                        window['-PROGRESS-'].update_bar(0)
                        report_name = 'Threat_Report.docx'
                        report_path = save_report(output, report_name)
                        window['-PROGRESS-'].update_bar(100)
                        response = sg.popup('Report Generated!', f'Report saved at: {report_path}', custom_text=('Open', 'Close'), keep_on_top=True)
                        if response == 'Open':
                            if os.name == 'nt':  # For Windows
                                os.startfile(report_path)
                            elif os.name == 'posix':  # For macOS and Linux
                                if sys.platform == 'darwin':  # Specifically for macOS
                                    subprocess.call(('open', report_path))
                                else:  # For Linux
                                    subprocess.call(('xdg-open', report_path))
                        window['-STATUS-'].update('Done')
            except openai.AuthenticationError:
                sg.popup('Authentication Error', 'Incorrect API key provided. Please check your API key and try again.')
                window['-STATUS-'].update('Authentication Error')
            except openai.BadRequestError:
                sg.popup('Bad Request Error', 'The request was invalid. Please check your input and try again.')
                window['-STATUS-'].update('Invalid Request Error')
            except openai.RateLimitError:
                sg.popup('Rate Limit Error', 'Rate limit exceeded. Please wait and try again.')
                window['-STATUS-'].update('Rate Limit Error')
            except openai.APIConnectionError:
                sg.popup('API Connection Error', 'Failed to connect to the API. Please check your network connection and try again.')
                window['-STATUS-'].update('API Connection Error')
            except openai.APIError:
                sg.popup('API Error', 'An error occurred with the API. Please try again later.')
                window['-STATUS-'].update('API Error')
            except Exception as e:
                sg.popup('An unexpected error occurred', str(e))
                window['-STATUS-'].update('Unexpected Error')

        elif event == 'Clear':
            window['-FILE_PATH-'].update('')
            window['-OUTPUT-'].update('')
            window['-PROGRESS-'].update_bar(0)  # Reset the progress bar
            window['-STATUS-'].update('- Ready -')  # Update status to Ready
            save_config(analyze_file_path='', analyze_output='')

        elif event == '-BUILD_HYPOTHESIS-':
            if client is None:
                sg.popup('API key is not set!')
                continue

            threat_report_path = values['-THREAT_REPORT_FILE_PATH-']
            if not threat_report_path:
                sg.popup('Error', 'No threat report file selected. Please select a threat report file.')
                continue
            window['-STATUS-'].update('Building threat hypothesis...')
            build_threat_hypothesis(client, threat_report_path, window)

            if values['-SAVE_HYPOTHESIS-']:
                save_config(hypothesis_file_path=threat_report_path, hypothesis_output=window['-THREAT_HYPOTHESIS-'].get())

            if values['-EXPORT_HYPOTHESIS-']:
                window['-STATUS-'].update('Generating Word document...')
                window['-PROGRESS-'].update_bar(0)
                report_name = 'Hypothesis_Report.docx'
                report_path = save_report(window['-THREAT_HYPOTHESIS-'].get(), report_name)
                window['-PROGRESS-'].update_bar(100)
                response = sg.popup('Report Generated!', f'Report saved at: {report_path}', custom_text=('Open', 'Close'), keep_on_top=True)
                if response == 'Open':
                    if os.name == 'nt':  # For Windows
                        os.startfile(report_path)
                    elif os.name == 'posix':  # For macOS and Linux
                        if sys.platform == 'darwin':  # Specifically for macOS
                            subprocess.call(('open', report_path))
                        else:  # For Linux
                            subprocess.call(('xdg-open', report_path))
                window['-STATUS-'].update('Done')

        elif event == '-CLEAR_HYPOTHESIS-':
            window['-THREAT_REPORT_FILE_PATH-'].update('')
            window['-THREAT_HYPOTHESIS-'].update('')
            window['-PROGRESS-'].update_bar(0)  # Reset the progress bar
            window['-STATUS-'].update('- Ready -')  # Update status to Ready
            save_config(hypothesis_file_path='', hypothesis_output='')

        # Enable or disable the Alerts Path based on the checkbox
        elif event == '-INCLUDE_ALERTS-':
            is_checked = values['-INCLUDE_ALERTS-']
            print(f"Checkbox state: {is_checked}")  # Debugging statement
            window['-ALERTS_FILE_PATH-'].update(disabled=not is_checked)
            window['-ALERTS_FILE_BROWSE-'].update(disabled=not is_checked)

        elif event == '-ANALYZE_PCAP-':
            pcap_path = values['-PCAP_FILE_PATH-']
            include_alerts = values['-INCLUDE_ALERTS-']
            alerts_path = values['-ALERTS_FILE_PATH-'] if include_alerts else None

            if not pcap_path:
                sg.popup('Error', 'Please select a PCAP file.')
                continue

            window['-STATUS-'].update('Analyzing PCAP...')
            window['-PROGRESS-'].update_bar(0)
            try:
                # Analyze PCAP file
                pcap_results = analyze_pcap_file(window, pcap_path, alerts_path)
                window['-PCAP_RESULTS-'].update(pcap_results)

               # Prepare prompt for OpenAI API
                prompt = (
                    "Analyze the following summarized network traffic for anomalies or potential threats. "
                    "Provide a detailed report that includes:\n\n"
                    "1. **Unique URLs and Domain Names:**\n"
                    "- Identify and list all unique URLs and domain names accessed within the network traffic.\n"
                    "- Highlight any suspicious or potentially malicious domains that may indicate phishing or C2 activity.\n\n"
                    "2. **Downloaded Files:**\n"
                    "- List all files downloaded over the network, including their types and potential risks.\n"
                    "- Pay special attention to executable files and other potentially harmful content.\n\n"
                    "3. **Network Flow Relationships:**\n"
                    "- Map out the network flow relationships, detailing the communication patterns between different IP addresses and ports.\n"
                    "- Identify any unusual or unexpected traffic patterns that could suggest lateral movement or data exfiltration.\n\n"
                    "4. **Indicators of Compromise (IoCs):**\n"
                    "- Extract and list any IoCs found in the traffic, such as IP addresses, file hashes, or specific URLs associated with known threats.\n\n"
                    "5. **Threat Context and Recommendations:**\n"
                    "- Provide context for the identified threats, including possible attack vectors and threat actor profiles.\n"
                    "- Offer actionable recommendations for mitigating identified threats and improving network security posture.\n\n"
                    "Ensure the report is clear and concise, suitable for both technical SOC analysts and non-technical stakeholders. "
                    "Use tables and charts where applicable to enhance readability and understanding.\n\n"
                    f"Network Traffic Summary:\n{pcap_results}"
                )
                
                # If alerts are included, add them to the prompt
                if include_alerts and alerts_path:
                    alerts_data = read_file(alerts_path)
                    prompt += (
                        "\n\nAdditionally, consider the following alerts data from Network Detection systems. "
                        "These alerts provide insights into potential security incidents and anomalies detected in the network. "
                        "Please analyze these alerts in conjunction with the network traffic to identify correlations, "
                        "validate potential threats, and assess the overall security posture:\n"
                        f"{alerts_data}"
                    )

                # Send combined data to OpenAI API for analysis
                window['-STATUS-'].update('Sending data to AI for analysis...')
                window['-PROGRESS-'].update_bar(50)
                pcap_analysis = call_gpt(client, prompt)
                window['-PCAP_RESULTS-'].update('\n\n', append=True)
                window['-PCAP_RESULTS-'].update(pcap_analysis, append=True)

                window['-STATUS-'].update('Analysis complete.')
                window['-PROGRESS-'].update_bar(100)

                # Save or export if options are selected
                if values['-SAVE_PCAP_RESULTS-']:
                    save_config(pcap_file_path=pcap_path, pcap_output=pcap_analysis, pcap_alerts_path=alerts_path)

                if values['-EXPORT_PCAP_RESULTS-']:
                    window['-STATUS-'].update('Generating Word document...')
                    window['-PROGRESS-'].update_bar(0)
                    report_name = 'PCAP_Analysis_Report.docx'
                    report_path = save_report(pcap_analysis, report_name)
                    window['-PROGRESS-'].update_bar(100)
                    response = sg.popup('Report Generated!', f'Report saved at: {report_path}', custom_text=('Open', 'Close'), keep_on_top=True)
                    if response == 'Open':
                        if os.name == 'nt':  # For Windows
                            os.startfile(report_path)
                        elif os.name == 'posix':  # For macOS and Linux
                            if sys.platform == 'darwin':  # Specifically for macOS
                                subprocess.call(('open', report_path))
                            else:  # For Linux
                                subprocess.call(('xdg-open', report_path))
                    window['-STATUS-'].update('Done')
            except Exception as e:
                sg.popup('An error occurred during PCAP analysis', str(e))
                window['-STATUS-'].update('Error')

        elif event == '-CLEAR_PCAP_RESULTS-':
            window['-PCAP_FILE_PATH-'].update('')
            window['-PCAP_RESULTS-'].update('')
            window['-ALERTS_FILE_PATH-'].update('')
            window['-PROGRESS-'].update_bar(0)  # Reset the progress bar
            window['-STATUS-'].update('- Ready -')  # Update status to Ready
            save_config(pcap_file_path='', pcap_output='', pcap_alerts_path='')

        elif event == '-BUILD_RULE-':
        # Handle building the detection rule using OpenAI API
            conversation_history = build_rule(client, window, values, conversation_history)

            # Handle Save I/O and Export Rule options
            if values['-SAVE_RULE-']:
                save_config(rule_output=window['-RULE_OUTPUT-'].get())

            # Handle Save I/O and Export Rule options
            if values['-SAVE_RULE-']:
                save_config(rule_output=window['-RULE_OUTPUT-'].get(), prompt_input=window['-PROMPT_INPUT-'].get())

            if values['-EXPORT_RULE-']:
                window['-STATUS-'].update('Generating Word document...')
                window['-PROGRESS-'].update_bar(0)
                report_name = 'Detection_Rule.docx'
                report_path = save_report(window['-RULE_OUTPUT-'].get(), report_name)
                window['-PROGRESS-'].update_bar(100)
                response = sg.popup('Report Generated!', f'Report saved at: {report_path}', custom_text=('Open', 'Close'), keep_on_top=True)
                if response == 'Open':
                    if os.name == 'nt':  # For Windows
                        os.startfile(report_path)
                    elif os.name == 'posix':  # For macOS and Linux
                        if sys.platform == 'darwin':  # Specifically for macOS
                            subprocess.call(('open', report_path))
                        else:  # For Linux
                            subprocess.call(('xdg-open', report_path))
                window['-STATUS-'].update('Done')
  
        elif event == '-CLEAR_RULE-':
            window['-PROMPT_INPUT-'].update('')
            window['-RULE_OUTPUT-'].update('')
            window['-PROGRESS-'].update_bar(0)  # Reset the progress bar
            window['-STATUS-'].update('- Ready -')  # Update status to Ready
            save_config(prompt_input='', rule_output='')

        elif event == '-START_SHELL-':
            # Enable the input and send button when Start is pressed
            window['-SHELL_PROMPT_INPUT-'].update(disabled=False)
            window['-SEND_SHELL-'].update(disabled=False)
        
        elif event == '-SEND_SHELL-':
            # Handle sending shell command
            command = values['-SHELL_PROMPT_INPUT-']
            ai_only = values['-AI_ONLY-']  # Get the checkbox state
            window['-STATUS-'].update('Executing command...')
            window['-PROGRESS-'].update_bar(0)
            
            try:
                shell_output = execute_command(window, command, ai_only=ai_only)
                window['-STATUS-'].update('Command executed successfully.')
                window['-PROGRESS-'].update_bar(100)
            except Exception as e:
                window['-STATUS-'].update(f'Error: {str(e)}')
                window['-PROGRESS-'].update_bar(0)
            
            # Add \n\n to separate the outputs, but skip this for the first execution
            if not first_send_shell:
                window['-SHELL_OUTPUT-'].update('\n\n', append=True)
            else:
                first_send_shell = False  # Set the flag to False after the first execution
            
            # Append the new shell output to the existing content
            window['-SHELL_OUTPUT-'].update(shell_output, append=True)

            # Clear the input field after sending
            window['-SHELL_PROMPT_INPUT-'].update('')

        elif event == '-CLEAR_SHELL-':
            # Clear input and output
            window['-SHELL_PROMPT_INPUT-'].update('')
            window['-SHELL_OUTPUT-'].update('')
            window['-PROGRESS-'].update_bar(0)  # Clear the progress bar
            window['-STATUS-'].update('- Ready -')  # Reset status
            first_send_shell = True  # Reset the flag when cleared

        elif event == '-DONE_SHELL-':
            # Disable input and send button when Done is pressed
            window['-SHELL_PROMPT_INPUT-'].update(disabled=True)
            window['-SEND_SHELL-'].update(disabled=True)

            # Save and export session if checkboxes are checked
            shell_output = window['-SHELL_OUTPUT-'].get()
            
            if values['-SAVE_SHELL_SESSION-']:
                file_name = save_to_file(shell_output, 'Shell_Session', '.txt')
                sg.popup('Session Saved', f'Session saved as {file_name}')
            
            if values['-EXPORT_SHELL_SESSION-']:
                docx_name = save_report(shell_output, 'Shell_Session.docx')
                if docx_name:
                    response = sg.popup('Session Exported', f'Session exported as {docx_name}', custom_text=('Open', 'Close'))
                    if response == 'Open':
                        if os.name == 'nt':  # Windows
                            os.startfile(docx_name)
                        elif os.name == 'posix':  # macOS and Linux
                            if sys.platform == 'darwin':  # macOS
                                subprocess.call(('open', docx_name))
                            else:  # Linux
                                subprocess.call(('xdg-open', docx_name))
                else:
                    sg.popup('Error', 'Failed to export session.')

        elif event == 'API Key':
            api_key_win = api_key_window(api_key)
            while True:
                api_key_event, api_key_values = api_key_win.read()
                if api_key_event in (sg.WINDOW_CLOSED, 'Exit'):
                    break
                elif api_key_event == 'Save API Key':
                    api_key = api_key_values['-API_KEY-']
                    if api_key:
                        try:
                            client = openai.OpenAI(api_key=api_key)
                            client.chat.completions.create(
                                model='gpt-4o',
                                messages=[{'role': 'system', 'content': 'Test message'}],
                                max_tokens=1,
                                n=1,
                                stop=None,
                                temperature=0.7
                            )
                            sg.popup('API key saved securely!')
                        except openai.AuthenticationError:
                            sg.popup('Authentication Error', 'Incorrect API key provided. Please check your API key and try again.')
                            client = None
                        save_config(api_key=api_key)
                        break
            api_key_win.close()

        elif event == 'Theme':
            theme_win = theme_window(theme)
            while True:
                theme_event, theme_values = theme_win.read()
                if theme_event in (sg.WINDOW_CLOSED, 'Exit'):
                    break
                elif theme_event == 'Save Theme':
                    theme = theme_values['-THEME-']
                    sg.theme(theme)
                    sg.popup('Theme saved securely!')
                    window.close()
                    layout = create_gui_layout()
                    window = sg.Window('.:: ThreatScout ::.', layout, size=(805, 625), resizable=True, finalize=True)
                    save_config(theme=theme)
                    client = openai.OpenAI(api_key=api_key) if api_key else None
                    break
            theme_win.close()

        elif event == 'About': 
            sg.popup('About',
                    "ThreatScout is a Threat Hunting assist tool powered by OpenAI GPT.\n\n"
                    "Purpose: The tool is designed to assist cybersecurity professionals in analyzing threat data and generating threat hypotheses.\n\n"
                    "Framework Alignment:\n\n"
                    "- PEAK Framework: ThreatScout aligns with the PEAK framework by facilitating hypothesis-driven threat hunting through preparation, execution, and action phases.\n\n"
                    "- ABLE Framework: The tool integrates the ABLE framework, focusing on Actor, Behavior, Location, and Evidence to enhance hypothesis generation.\n\n"
                    "Credit: The PEAK framework was developed by Splunk. For more information, visit the Splunk blog:\n"
                    "https://www.splunk.com/en_us/blog/security/peak-hypothesis-driven-threat-hunting.html",
                    image=logo_image_path
    )

    window.close()

if __name__ == "__main__":
    main()