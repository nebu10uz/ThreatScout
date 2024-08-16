import os
import sys
import json
import subprocess
from cryptography.fernet import Fernet, InvalidToken
import openai
import PySimpleGUI as sg
import pypandoc

CONFIG_FILE = 'config.json'
KEY_FILE = 'key.key'

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

def save_config(api_key=None, theme=None, file_path=None, output=None):
    config = {}
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, 'r') as config_file:
            config = json.load(config_file)
    if api_key:
        config['ENCRYPTED_OPENAI_API_KEY'] = encrypt_api_key(api_key)
    if theme:
        config['THEME'] = theme
    if file_path is not None:
        config['FILE_PATH'] = file_path
    if output is not None:
        config['OUTPUT'] = output
    with open(CONFIG_FILE, 'w') as config_file:
        json.dump(config, config_file)

def load_config():
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, 'r') as config_file:
            config = json.load(config_file)
        encrypted_api_key = config.get('ENCRYPTED_OPENAI_API_KEY')
        theme = config.get('THEME', 'DarkGrey11')
        file_path = config.get('FILE_PATH', '')
        output = config.get('OUTPUT', '')
        if encrypted_api_key:
            return decrypt_api_key(encrypted_api_key), theme, file_path, output
    return None, 'DarkGrey11', '', ''

def call_gpt(client, prompt):
    messages = [
        {'role': 'system', 'content': 'You are a cybersecurity SOC analyst with more than 25 years of experience.'},
        {'role': 'user', 'content': prompt}
    ]
    response = client.chat.completions.create(
        model='gpt-4o',
        messages=messages,
        max_tokens=2048,
        n=1,
        stop=None,
        temperature=0.7
    )
    return response.choices[0].message.content.strip()

def analyze_threat_data(client, file_path, window):
    try:
        with open(file_path, 'r') as file:
            raw_data = file.read()
    except FileNotFoundError:
        sg.popup('Error', 'No file selected or file not found. Please select a valid threat data file.')
        return None, None, None

    window['-PROGRESS-'].update_bar(0)
    window['-STATUS-'].update('Analyzing threats...')
    identified_threats = call_gpt(client, f'Analyze the following threat data and identify potential threats: {raw_data}')
    window['-PROGRESS-'].update_bar(33)
    window['-STATUS-'].update('Extracting IOCs...')
    extracted_iocs = call_gpt(client, f'Extract all indicators of compromise (IoCs) from the following threat data: {raw_data}')
    window['-PROGRESS-'].update_bar(66)
    window['-STATUS-'].update('Providing threat context...')
    threat_context = call_gpt(client, f'Provide a detailed context or narrative behind the identified threats in this data: {raw_data}')
    window['-PROGRESS-'].update_bar(100)
    window['-STATUS-'].update('Analysis complete.')

    return identified_threats, extracted_iocs, threat_context

def markdown_to_docx(markdown_text: str, output_file: str):
    # Convert the markdown text directly to a DOCX file
    try:
        pypandoc.convert_text(markdown_text, 'docx', format='md', outputfile=output_file)
    except RuntimeError as e:
        print(f"Error during conversion: {e}")

def save_report(output, report_name):
    if not os.path.exists('Reports'):
        os.makedirs('Reports')
    report_path = os.path.join('Reports', report_name)
    markdown_to_docx(output, report_path)
    return report_path

def create_gui_layout():
    layout = [
        [sg.Menu([['File', ['Exit']], ['Settings', ['API Key', 'Theme']], ['Help', ['About']]])],
        [sg.TabGroup([[
            sg.Tab('Analyze Threat', [
                [sg.HorizontalSeparator()],
                [sg.Text('Threat Data Path:'), sg.InputText(key='-FILE_PATH-', expand_x=True), sg.FileBrowse()],
                [sg.HorizontalSeparator()],
                [sg.Frame('Output', [
                    [sg.Multiline(size=(124, 20), key='-OUTPUT-', disabled=True, expand_x=True, expand_y=True)]
                ], expand_x=True, expand_y=True)],
                [sg.HorizontalSeparator()],
                [sg.Column([
                    [sg.Button('Analyze', size=(10, 1)), sg.Button('Clear', size=(10, 1)), sg.Push(), sg.Text('Options:'), sg.Checkbox('Save I/O', key='-SAVE-'), sg.Checkbox('Export Report', key='-EXPORT-')]
                ], element_justification='center', expand_x=True)]
            ], key='-ANALYZE_TAB-')
        ]], expand_x=True, expand_y=True)],
        [sg.HorizontalSeparator()],
        [sg.Text('ThreatScout version 0.2'), sg.Push(), sg.Text('Progress:'), sg.ProgressBar(100, orientation='h', size=(15, 20), key='-PROGRESS-'), sg.VerticalSeparator(), sg.Text('Status:'), sg.Text('- Ready -', size=(25, 1), key='-STATUS-', justification='right')]
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

def main():
    api_key, theme, saved_file_path, saved_output = load_config()
    sg.theme(theme)
    sg.set_options(font=('Helvetica', 12))
    layout = create_gui_layout()
    window = sg.Window(':: ThreatScout ::', layout, size=(805, 480), resizable=True, finalize=True)
    client = openai.OpenAI(api_key=api_key) if api_key else None

    if saved_file_path:
        window['-FILE_PATH-'].update(saved_file_path)
    if saved_output:
        window['-OUTPUT-'].update(saved_output)

    while True:
        event, values = window.read()
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
                        save_config(file_path=file_path, output=output)
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
            window['-PROGRESS-'].update_bar(0)  # Add this line to reset the progress bar
            window['-STATUS-'].update('- Ready -')  # Update status to Ready
            save_config(file_path='', output='')
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
                    window = sg.Window(':: ThreatScout ::', layout, size=(805, 480), resizable=True, finalize=True)
                    save_config(theme=theme)
                    client = openai.OpenAI(api_key=api_key) if api_key else None
                    break
            theme_win.close()
        elif event == 'About':
            sg.popup('About', 'This is a Threat Hunting Tool powered by OpenAI GPT.')

    window.close()

if __name__ == "__main__":
    main()