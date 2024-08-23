import os
import sys
import json
import subprocess
from cryptography.fernet import Fernet, InvalidToken
import openai
import PySimpleGUI as sg
import pypandoc
from docx import Document

THREATSCOUT_VERSION = 'ThreatScout version 0.3'
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

def save_config(api_key=None, theme=None, analyze_file_path=None, analyze_output=None, hypothesis_file_path=None, hypothesis_output=None):
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
    with open(CONFIG_FILE, 'w') as config_file:
        json.dump(config, config_file)

def load_config():
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, 'r') as config_file:
            config = json.load(config_file)
        encrypted_api_key = config.get('ENCRYPTED_OPENAI_API_KEY')
        theme = config.get('THEME', 'DarkGrey11')
        analyze_file_path = config.get('ANALYZE_FILE_PATH', '')
        analyze_output = config.get('ANALYZE_OUTPUT', '')
        hypothesis_file_path = config.get('HYPOTHESIS_FILE_PATH', '')
        hypothesis_output = config.get('HYPOTHESIS_OUTPUT', '')
        if encrypted_api_key:
            return decrypt_api_key(encrypted_api_key), theme, analyze_file_path, analyze_output, hypothesis_file_path, hypothesis_output
    return None, 'DarkGrey11', '', '', '', ''

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

def extract_text_from_docx(file_path):
    doc = Document(file_path)
    full_text = []
    for para in doc.paragraphs:
        full_text.append(para.text)
    return '\n'.join(full_text)

def read_file(file_path):
    if file_path.endswith('.docx'):
        return extract_text_from_docx(file_path)
    else:
        with open(file_path, 'r', encoding='utf-8') as file:
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
    extracted_iocs = call_gpt(client, f'Extract all indicators of compromise (IoCs) from the following threat data: {raw_data}')
    window['-PROGRESS-'].update_bar(66)
    window['-STATUS-'].update('Providing threat context...')
    threat_context = call_gpt(client, f'Provide a detailed context or narrative behind the identified threats in this data: {raw_data}')
    window['-PROGRESS-'].update_bar(100)
    window['-STATUS-'].update('Analysis complete.')
    return identified_threats, extracted_iocs, threat_context

def markdown_to_docx(markdown_text: str, output_file: str):
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
            ], key='-HYPOTHESIS_TAB-')
        ]], expand_x=True, expand_y=True)],
        [sg.HorizontalSeparator()],
        [sg.Text(THREATSCOUT_VERSION), sg.Push(), sg.Text('Progress:'), sg.ProgressBar(100, orientation='h', size=(15, 20), key='-PROGRESS-'), sg.VerticalSeparator(), sg.Text('Status:'), sg.Text('- Ready -', size=(25, 1), key='-STATUS-', justification='right')]
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

def main():
    api_key, theme, analyze_file_path, analyze_output, hypothesis_file_path, hypothesis_output = load_config()
    sg.theme(theme)
    sg.set_options(font=('Helvetica', 12))
    layout = create_gui_layout()
    window = sg.Window('.:: ThreatScout ::.', layout, size=(805, 600), resizable=True, finalize=True)

    client = openai.OpenAI(api_key=api_key) if api_key else None

    if analyze_file_path:
        window['-FILE_PATH-'].update(analyze_file_path)
    if analyze_output:
        window['-OUTPUT-'].update(analyze_output)
    if hypothesis_file_path:
        window['-THREAT_REPORT_FILE_PATH-'].update(hypothesis_file_path)
    if hypothesis_output:
        window['-THREAT_HYPOTHESIS-'].update(hypothesis_output)

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
                    window = sg.Window('.:: ThreatScout ::.', layout, size=(805, 600), resizable=True, finalize=True)
                    save_config(theme=theme)
                    client = openai.OpenAI(api_key=api_key) if api_key else None
                    break
            theme_win.close()
        elif event == 'About':
            sg.popup('About', (
                "ThreatScout is a Threat Hunting assit tool powered by OpenAI GPT.\n\n"
                "Purpose: The tool is designed to assist cybersecurity professionals in analyzing threat data and generating threat hypotheses.\n\n"
                "Framework Alignment:\n\n"
                "- PEAK Framework: ThreatScout aligns with the PEAK framework by facilitating hypothesis-driven threat hunting through preparation, execution, and action phases.\n\n"
                "- ABLE Framework: The tool integrates the ABLE framework, focusing on Actor, Behavior, Location, and Evidence to enhance hypothesis generation.\n\n"
                "Credit: The PEAK framework was developed by Splunk. For more information, visit the Splunk blog:\n"
                "https://www.splunk.com/en_us/blog/security/peak-hypothesis-driven-threat-hunting.html"
            ))

    window.close()

if __name__ == "__main__":
    main()