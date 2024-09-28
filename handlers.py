import PySimpleGUI as sg
import openai
from config import save_config
from gui import create_gui_layout, api_key_window, theme_window, ai_model_window
from ai import analyze_threat_data, build_threat_hypothesis, build_rule, execute_command, configure_interpreter, analyze_pcap
from utils import save_to_file, save_report, open_file, read_file
from datetime import datetime
from globals import global_window


def handle_events(window, config, conversation_history, first_send_shell):
    while True:
        event, values = window.read()
        print(f"Event: {event}")  # Debugging statement

        if event in (sg.WINDOW_CLOSED, 'Exit'):
            break

        elif event == 'Analyze':
            handle_analyze(window, values, config)

        elif event == 'Clear':
            handle_clear(window, config)

        elif event == '-BUILD_HYPOTHESIS-':
            handle_build_hypothesis(window, values, config)

        elif event == '-CLEAR_HYPOTHESIS-':
            handle_clear_hypothesis(window, config)

        elif event == '-INCLUDE_ALERTS-':
            handle_include_alerts(window, values)

        elif event == '-ANALYZE_PCAP-':
            handle_analyze_pcap(window, values, config)

        elif event == '-CLEAR_PCAP_RESULTS-':
            handle_clear_pcap_results(window, config)

        elif event == '-BUILD_RULE-':
            conversation_history = handle_build_rule(window, values, conversation_history, config)

        elif event == '-CLEAR_RULE-':
            handle_clear_rule(window, config)

        elif event == '-START_SHELL-':
            handle_start_shell(window, config)

        elif event == '-SEND_SHELL-' or event == '-SHELL_PROMPT_INPUT--SEND_SHELL-':
            first_send_shell = handle_send_shell(window, values, config, first_send_shell)

        elif event == '-CLEAR_SHELL-':
            handle_clear_shell(window, config)
            first_send_shell = True

        elif event == '-DONE_SHELL-':
            handle_done_shell(window, values)

        elif event == 'API Key':
            config.api_key = handle_api_key(config.api_key)
            configure_interpreter(config)

        elif event == 'AI Model':
            config = handle_ai_model(window, config)
            configure_interpreter(config)
            if global_window and not global_window.was_closed():
                global_window['-AI-MODEL-'].update('Local AI' if config.use_local_model else 'OpenAI')

        elif event == 'Theme':
            window = handle_theme(window, config)

        elif event == 'About':
            handle_about()

    window.close()

def handle_clear_rule(window, config):
    window['-PROMPT_INPUT-'].update('')
    window['-RULE_OUTPUT-'].update('')
    window['-PROGRESS-'].update_bar(0)
    window['-STATUS-'].update('- Ready -')
    config.update(prompt_input='', rule_output='')

def handle_analyze(window, values, config):
    file_path = values['-FILE_PATH-']
    if not file_path:
        sg.popup('Error', 'No file selected. Please select a threat data file.')
        return
    
    window['-STATUS-'].update('Starting analysis...')
    try:
        identified_threats, extracted_iocs, threat_context = analyze_threat_data(config, file_path, window)
        
        full_analysis = f"Identified Threats:\n{identified_threats}\n\n"
        full_analysis += f"Extracted IoCs:\n{extracted_iocs}\n\n"
        full_analysis += f"Threat Context:\n{threat_context}"
        
        window['-OUTPUT-'].update(full_analysis)
        window['-STATUS-'].update('Analysis complete.')
        window['-PROGRESS-'].update_bar(100)
        
        if values['-SAVE-']:
            config.update(analyze_file_path=file_path, analyze_output=full_analysis)
        
        if values['-EXPORT-']:
            report_name = 'Threat_Analysis_Report.docx'
            report_path = save_report(full_analysis, report_name)
            if report_path:
                response = sg.popup('Report Generated!', f'Report saved at: {report_path}', custom_text=('Open', 'Close'))
                if response == 'Open':
                    open_file(report_path)
    except Exception as e:
        sg.popup('An error occurred during analysis', str(e))
        window['-STATUS-'].update('Error')

def handle_clear(window, config):
    window['-FILE_PATH-'].update('')
    window['-OUTPUT-'].update('')
    window['-PROGRESS-'].update_bar(0)
    window['-STATUS-'].update('- Ready -')
    config.update(analyze_file_path='', analyze_output='')

def handle_build_hypothesis(window, values, config):
    threat_report_path = values['-THREAT_REPORT_FILE_PATH-']
    if not threat_report_path:
        sg.popup('Error', 'No threat report file selected. Please select a threat report file.')
        return
    
    window['-STATUS-'].update('Building threat hypothesis...')
    
    try:
        # Use the read_file function to handle different file types
        threat_report = read_file(threat_report_path)
    except FileNotFoundError:
        sg.popup('Error', 'File not found. Please select a valid threat report file.')
        return
    except Exception as e:
        sg.popup('Error', f'An error occurred while reading the file: {str(e)}')
        return

    hypothesis = build_threat_hypothesis(threat_report, window, config)
    window['-THREAT_HYPOTHESIS-'].update(hypothesis)

    if values['-SAVE_HYPOTHESIS-']:
        config.update(hypothesis_file_path=threat_report_path, hypothesis_output=hypothesis)

    if values['-EXPORT_HYPOTHESIS-']:
        window['-STATUS-'].update('Generating Word document...')
        window['-PROGRESS-'].update_bar(0)
        report_name = 'Hypothesis_Report.docx'
        report_path = save_report(hypothesis, report_name)
        window['-PROGRESS-'].update_bar(100)
        response = sg.popup('Report Generated!', f'Report saved at: {report_path}', custom_text=('Open', 'Close'), keep_on_top=True)
        if response == 'Open':
            open_file(report_path)
        window['-STATUS-'].update('Done')

def handle_clear_hypothesis(window, config):
    window['-THREAT_REPORT_FILE_PATH-'].update('')
    window['-THREAT_HYPOTHESIS-'].update('')
    window['-PROGRESS-'].update_bar(0)
    window['-STATUS-'].update('- Ready -')
    config.update(hypothesis_file_path='', hypothesis_output='')

def handle_include_alerts(window, values):
    is_checked = values['-INCLUDE_ALERTS-']
    print(f"Checkbox state: {is_checked}")  # Debugging statement
    window['-ALERTS_FILE_PATH-'].update(disabled=not is_checked)
    window['-ALERTS_FILE_BROWSE-'].update(disabled=not is_checked)

def handle_analyze_pcap(window, values, config):
    analyze_pcap(window, values, config)

def handle_clear_pcap_results(window, config):
    window['-PCAP_FILE_PATH-'].update('')
    window['-PCAP_RESULTS-'].update('')
    window['-ALERTS_FILE_PATH-'].update('')
    window['-PROGRESS-'].update_bar(0)
    window['-STATUS-'].update('- Ready -')
    config.update(pcap_file_path='', pcap_output='', pcap_alerts_path='')

def handle_build_rule(window, values, conversation_history, config):
    conversation_history = build_rule(window, values, conversation_history, config)
    
    if values['-SAVE_RULE-']:
        config.update(prompt_input=values['-PROMPT_INPUT-'], rule_output=window['-RULE_OUTPUT-'].get())
    
    if values['-EXPORT_RULE-']:
        window['-STATUS-'].update('Exporting rule...')
        window['-PROGRESS-'].update_bar(0)
        rule_content = window['-RULE_OUTPUT-'].get()
        file_name = 'Detection_Rule.docx'
        
        try:
            report_path = save_report(rule_content, file_name)
            if report_path:
                window['-PROGRESS-'].update_bar(100)
                window['-STATUS-'].update('Rule exported successfully.')
                response = sg.popup('Rule Exported', f'Rule has been exported to {report_path}', custom_text=('Open', 'Close'), keep_on_top=True)
                if response == 'Open':
                    open_file(report_path)
            else:
                raise Exception("Failed to save the report")
        except Exception as e:
            window['-STATUS-'].update('Error exporting rule.')
            sg.popup_error('Error', f'Failed to export rule: {str(e)}')
        
        window['-PROGRESS-'].update_bar(0)
        window['-STATUS-'].update('- Ready -')
    
    return conversation_history

def handle_clear_rule(window, config):
    window['-PROMPT_INPUT-'].update('')
    window['-RULE_OUTPUT-'].update('')
    window['-PROGRESS-'].update_bar(0)
    window['-STATUS-'].update('- Ready -')
    config.update(prompt_input='', rule_output='')

def handle_start_shell(window, config):
    if not config.api_key and not config.use_local_model:
        sg.popup('API key is not set!')
        return

    window['-SHELL_PROMPT_INPUT-'].update(disabled=False)
    window['-SEND_SHELL-'].update(disabled=False)

def handle_send_shell(window, values, config, first_send_shell):
    if not config.api_key and not config.use_local_model:
        sg.popup('API key is not set!')
        return first_send_shell

    command = values['-SHELL_PROMPT_INPUT-'].strip()
    if not command:
        sg.popup('Error', 'The shell prompt input is empty. Please enter a command.')
        return first_send_shell

    window['-STATUS-'].update('Executing command...')
    window['-PROGRESS-'].update_bar(0)

    try:
        if config.use_local_model:
            # For Local AI, only send the current command
            response = execute_command(window, values, command, config, local_only=True)
        else:
            # For OpenAI, use the existing functionality
            response = execute_command(window, values, command, config)
        
        ai_only = values['-AI_ONLY-']
        if not ai_only:
            # If AI_ONLY is not checked, display both command and response
            full_output = f"Command: {command}\n\nResponse:\n{response}"
        else:
            # If AI_ONLY is checked, display only the AI response
            full_output = response

        # Add \n\n to separate the outputs, but skip this for the first execution
        if not first_send_shell:
            window['-SHELL_OUTPUT-'].update('\n\n', append=True)
        else:
            first_send_shell = False  # Set the flag to False after the first execution

        window['-SHELL_OUTPUT-'].update(full_output, append=True)
        window['-STATUS-'].update('Command executed.')
        window['-PROGRESS-'].update_bar(100)
        
        # Clear the input field after sending
        window['-SHELL_PROMPT_INPUT-'].update('')

    except Exception as e:
        error_message = f"An error occurred while executing the command: {str(e)}"
        window['-SHELL_OUTPUT-'].update(error_message, append=True)
        window['-STATUS-'].update('Error')
        window['-PROGRESS-'].update_bar(0)
        print(error_message)  # Debug output

    return first_send_shell

def handle_clear_shell(window, config):
    window['-SHELL_PROMPT_INPUT-'].update('')
    window['-SHELL_OUTPUT-'].update('')
    window['-PROGRESS-'].update_bar(0)
    window['-STATUS-'].update('- Ready -')
    return True

def handle_done_shell(window, values):
    window['-SHELL_PROMPT_INPUT-'].update(disabled=True)
    window['-SEND_SHELL-'].update(disabled=True)

    shell_output = window['-SHELL_OUTPUT-'].get()
    
    current_time = datetime.now().strftime("%Y%m%d_%H%M%S")
    base_filename = f'Shell_Session_{current_time}'

    if values['-SAVE_SHELL_SESSION-']:
        file_name = save_to_file(shell_output, base_filename, '.txt')
        if file_name:
            sg.popup('Session Saved', f'Session saved as {file_name}')
        else:
            sg.popup('Error', 'Failed to save session.')
    
    if values['-EXPORT_SHELL_SESSION-']:
        window['-STATUS-'].update('Generating Word document...')
        window['-PROGRESS-'].update_bar(0)
        docx_name = save_report(shell_output,  f'Shell_Session.docx')
        window['-PROGRESS-'].update_bar(100)
        if docx_name:
            response = sg.popup('Session Exported', f'Session exported as {docx_name}', custom_text=('Open', 'Close'))
            if response == 'Open':
                open_file(docx_name)
        else:
            sg.popup('Error', 'Failed to export session.')
        window['-STATUS-'].update('Done')

def handle_api_key(api_key):
    api_key_win = api_key_window(api_key)
    while True:
        api_key_event, api_key_values = api_key_win.read()
        if api_key_event in (sg.WINDOW_CLOSED, 'Exit', 'Cancel'):
            break
        elif api_key_event == 'Save API Key':
            api_key = api_key_values['-API_KEY-']
            if api_key:
                try:
                    client = openai.OpenAI(api_key=api_key)
                    client.chat.completions.create(
                        model='gpt-4',
                        messages=[{'role': 'system', 'content': 'Test message'}],
                        max_tokens=1,
                        n=1,
                        stop=None,
                        temperature=0.7
                    )
                    sg.popup('API key saved securely!')
                    save_config(api_key=api_key)
                    break
                except openai.AuthenticationError:
                    sg.popup('Authentication Error', 'Incorrect API key provided. Please check your API key and try again.')
                    client = None
            else:
                sg.popup('Error', 'API key cannot be empty.')
    api_key_win.close()
    return api_key

def handle_theme(window, config):
    theme_win = theme_window(sg.theme())
    while True:
        theme_event, theme_values = theme_win.read()
        if theme_event in (sg.WINDOW_CLOSED, 'Exit', 'Cancel'):
            break
        elif theme_event == 'Save Theme':
            theme = theme_values['-THEME-']
            sg.theme(theme)
            sg.popup('Theme saved securely!')
            config.update(theme=theme)
            window.close()
            layout = create_gui_layout()
            window = sg.Window('.:: ThreatScout ::.', layout, size=(805, 625), resizable=True, finalize=True)
            break
    theme_win.close()
    return window

def handle_ai_model(window, config):
    ai_model_win = ai_model_window(config)
    settings_changed = False

    while True:
        ai_model_event, ai_model_values = ai_model_win.read()
        if ai_model_event in (sg.WINDOW_CLOSED, 'Cancel'):
            break
        elif ai_model_event == '-USE_LOCAL_MODEL-':
            ai_model_win['-LOCAL_MODEL_URL-'].update(disabled=not ai_model_values['-USE_LOCAL_MODEL-'])
        elif ai_model_event == 'Save Settings':
            new_use_local_model = ai_model_values['-USE_LOCAL_MODEL-']
            new_local_model_url = ai_model_values['-LOCAL_MODEL_URL-']
            new_supports_functions = ai_model_values['-SUPPORT_FUNCTIONS_YES-']
            if new_use_local_model and not new_local_model_url.startswith(('http://', 'https://')):
                sg.popup_error('Invalid URL', 'Please enter a valid URL starting with http:// or https://')
                continue
            config.update(use_local_model=new_use_local_model, local_model_url=new_local_model_url, supports_functions=new_supports_functions)
            settings_changed = True
            break
        elif ai_model_event == 'Reset Settings':
            if sg.popup_yes_no('Confirm Reset', 'Are you sure you want to reset AI Model settings to default?') == 'Yes':
                config.update(use_local_model=False, local_model_url='', supports_functions=True)
                ai_model_win['-USE_LOCAL_MODEL-'].update(False)
                ai_model_win['-LOCAL_MODEL_URL-'].update('')
                ai_model_win['-SUPPORT_FUNCTIONS_YES-'].update(True)
                ai_model_win['-SUPPORT_FUNCTIONS_NO-'].update(False)
                settings_changed = True
                break
    ai_model_win.close()
    if settings_changed:
        configure_interpreter(config)
        window['-SHELL_OUTPUT-'].update('')
        window['-SHELL_OUTPUT-'].Widget.delete('1.0', 'end')
        window['-PROGRESS-'].update_bar(0)
        window['-STATUS-'].update('- Ready -')
        # Update the AI model status in the main window
        window['-AI-MODEL-'].update('Local AI' if config.use_local_model else 'OpenAI')
        sg.popup('AI Model settings updated and conversation history cleared.')
    return config

def handle_about():
    sg.popup('About',
        "ThreatScout - Advanced AI-Powered Threat Hunting Assistant\n\n"
        "Purpose: ThreatScout leverages cutting-edge AI and large language models to revolutionize cybersecurity operations, offering tools for threat analysis, hypothesis generation, and detection rule creation.\n\n"
        "Key Features:\n"
        "• AI-Driven Threat Report Analyzer: Processes complex threat data for actionable insights\n"
        "• Hypothesis Builder: Generates threat hypotheses based on PEAK and ABLE frameworks\n"
        "• PCAP Analyzer: Examines network traffic using AI for advanced threat detection\n"
        "• GPT-Assisted Detection Rule Builder: Creates and optimizes custom detection rules\n"
        "• AI-Powered Local Shell: Provides an intelligent interface for threat hunting commands\n\n"
        "Frameworks:\n"
        "• PEAK (Preparation, Execution, Analysis, Knowledge): Guides hypothesis-driven threat hunting\n"
        "• ABLE (Actor, Behavior, Location, Evidence): Enhances threat hypothesis generation\n\n"
        "AI Integration: Utilizes OpenAI GPT or local AI models for intelligent analysis, automation, and assistance across all cybersecurity tasks.\n\n"
        "Inspired by advanced techniques from 'ChatGPT for Cybersecurity Cookbook' by Clint Bodungen.\n\n"
        "Credit: PEAK framework developed by Splunk (https://www.splunk.com/en_us/blog/security/peak-hypothesis-driven-threat-hunting.html)",
        image='Images/About_logo.png'
    )