import PySimpleGUI as sg
import traceback
from globals import global_window
from config import load_config, save_config, Config
from gui import create_gui_layout, api_key_window
from handlers import handle_events
from ai import configure_interpreter


def main():
    """Main function to run ThreatScout application"""

    global global_window
    config_data = load_config()
    config = Config(**config_data)

    # Set the theme before creating any windows
    sg.theme(config.theme)
    sg.set_options(font=('Helvetica', 12))

    # Create and show the main window
    layout = create_gui_layout()
    global_window = sg.Window('.:: ThreatScout ::.', layout, size=(805, 625), resizable=True, finalize=True)

    # Bind the Return key to the shell input element
    global_window['-SHELL_PROMPT_INPUT-'].bind('<Return>', '-SEND_SHELL-')

    # Check if API key is set
    if not config.api_key and not config.use_local_model:
        api_key_win = api_key_window('', finalize=True)
        api_key_win.bring_to_front()
        while True:
            api_key_event, api_key_values = api_key_win.read()
            if api_key_event in (sg.WINDOW_CLOSED, 'Exit', 'Cancel'):
                sg.popup('API key is required to use OpenAI services. Exiting program.')
                global_window.close()
                return
            elif api_key_event == 'Save API Key':
                api_key = api_key_values['-API_KEY-']
                if api_key:
                    config.api_key = api_key
                    save_config(api_key=api_key)
                    break
                else:
                    sg.popup('Error', 'API key cannot be empty.')
        api_key_win.close()

    # Load saved inputs and outputs
    if config.analyze_file_path:
        global_window['-FILE_PATH-'].update(config.analyze_file_path)
    if config.analyze_output:
        global_window['-OUTPUT-'].update(config.analyze_output)
    if config.hypothesis_file_path:
        global_window['-THREAT_REPORT_FILE_PATH-'].update(config.hypothesis_file_path)
    if config.hypothesis_output:
        global_window['-THREAT_HYPOTHESIS-'].update(config.hypothesis_output)
    if config.pcap_file_path:
        global_window['-PCAP_FILE_PATH-'].update(config.pcap_file_path)
    if config.pcap_output:
        global_window['-PCAP_RESULTS-'].update(config.pcap_output)
    if config.pcap_alerts_path:
        global_window['-ALERTS_FILE_PATH-'].update(config.pcap_alerts_path)
    if config.prompt_input:
        global_window['-PROMPT_INPUT-'].update(config.prompt_input)
    if config.rule_output:
        global_window['-RULE_OUTPUT-'].update(config.rule_output)

    # Configure the Interpreter whether local or OpenAI when using the Local Shell
    configure_interpreter(config)

    conversation_history = [{'role': 'system', 'content': 'You are a cybersecurity SOC analyst with more than 25 years of experience.'}]
    
    first_send_shell = True

    # Update AI model status
    global_window['-AI-MODEL-'].update('Local AI' if config.use_local_model else 'OpenAI')

    while True:
        try:
            event, values = global_window.read(timeout=100)
            if event in (sg.WINDOW_CLOSED, 'Exit', None):
                break

            handle_events(global_window, config, conversation_history, first_send_shell)

            # Update AI model status
            if global_window and not global_window.was_closed():
                global_window['-AI-MODEL-'].update('Local AI' if config.use_local_model else 'OpenAI')

            # Update first_send_shell if necessary
            if event == '-SEND_SHELL-':
                first_send_shell = False

        except Exception as e:
            print(f"An error occurred in the main loop: {str(e)}")
            print(traceback.format_exc())
            sg.popup_error(f"An error occurred: {str(e)}")
            break

    if global_window and not global_window.was_closed():
        global_window.close()

if __name__ == "__main__":
    main()