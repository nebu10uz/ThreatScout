import PySimpleGUI as sg


THREATSCOUT_VERSION = 'ThreatScout v0.0.7'

# Path to ThreatScout logo images
logo_image_path = 'Images/Docrop2.png'
text_image_path = 'Images/big_ThreatScout.png'
about_image_path = 'Images/About_logo.png'

def create_gui_layout():
    layout = [
        [sg.Image(filename=text_image_path, key='-THREATSCOUT-TXT-IMAGE-'), sg.Text('Threat Hunt Assist Tool'),
         sg.Push(),  # This will push the next elements to the far right
         sg.Image(filename=logo_image_path, key='-THREATSCOUTLOGO-IMAGE-', pad=((0, 0), (10, 0)))],
        [sg.Menu([['File', ['Exit']], ['Settings', ['API Key', 'AI Model', 'Theme']], ['Help', ['About']]])],
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
                [sg.Checkbox('Include Alerts', key='-INCLUDE_ALERTS-', default=False, enable_events=True)],
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
             [create_detection_rule_builder_tab()],
             [create_threat_hunt_local_shell_tab()]
            ], expand_x=True, expand_y=True)],
        [sg.HorizontalSeparator()],
        [sg.Text(THREATSCOUT_VERSION + ' :: ' + 'Powered by'),
         sg.Text('OpenAI', size=(10, 1), key='-AI-MODEL-'), 
         sg.Push(), 
         sg.Text('Progress:'), sg.ProgressBar(100, orientation='h', size=(15, 20), key='-PROGRESS-'), 
         sg.VerticalSeparator(), sg.Text('Status:'), sg.Text('- Ready -', size=(25, 1), key='-STATUS-', justification='right')]
    ]
    return layout

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
                      font=('Helvetica', 12, 'italic'))],
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

def api_key_window(api_key, finalize=False):
    layout = [
        [sg.Text('Enter your OpenAI API Key:')],
        [sg.Input(api_key, key='-API_KEY-', size=(50, 1), password_char='*')],  # Use password_char to mask input
        [sg.Button('Save API Key'), sg.Button('Cancel')]
    ]
    return sg.Window('API Key', layout, finalize=finalize)

def theme_window(current_theme):
    themes = sg.theme_list()
    layout = [
        [sg.Text('Select Theme:'), sg.Combo(themes, default_value=current_theme, key='-THEME-', readonly=True)],
        [sg.Button('Save Theme'), sg.Button('Cancel')]
    ]
    return sg.Window('Theme Settings', layout)

def ai_model_window(config):
    layout = [
        [sg.Checkbox('Use Local AI Model', default=config.use_local_model, key='-USE_LOCAL_MODEL-', enable_events=True)],
        [sg.Text('Local Model URL:'), sg.InputText(config.local_model_url or 'http://localhost:1234', key='-LOCAL_MODEL_URL-', disabled=not config.use_local_model)],
        [sg.Text('Support function calls:'), sg.Radio('Yes', 'FUNCTION_CALLS', default=config.supports_functions, key='-SUPPORT_FUNCTIONS_YES-'), 
         sg.Radio('No', 'FUNCTION_CALLS', default=not config.supports_functions, key='-SUPPORT_FUNCTIONS_NO-')],
        [sg.Button('Save Settings'), sg.Button('Reset Settings'), sg.Button('Cancel')]
    ]
    return sg.Window('AI Model Settings', layout, finalize=True)