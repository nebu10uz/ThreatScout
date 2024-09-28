import os
import json
from cryptography.fernet import Fernet, InvalidToken


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
        return None

def save_config(**kwargs):
    config = {}
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, 'r') as config_file:
            config = json.load(config_file)
    
    for key, value in kwargs.items():
        if key == 'api_key' and value:
            config['ENCRYPTED_OPENAI_API_KEY'] = encrypt_api_key(value)
        else:
            config[key.upper()] = value

    with open(CONFIG_FILE, 'w') as config_file:
        json.dump(config, config_file)

class Config:
    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)
        self.ai_only = kwargs.get('ai_only', False)

    def update(self, **kwargs):
        self.__dict__.update(kwargs)
        save_config(**kwargs)

def load_config():
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, 'r') as config_file:
            config = json.load(config_file)
        encrypted_api_key = config.get('ENCRYPTED_OPENAI_API_KEY')
        api_key = decrypt_api_key(encrypted_api_key) if encrypted_api_key else None
        return {
            'api_key': api_key,
            'theme': config.get('THEME', 'DarkGrey16'),
            'analyze_file_path': config.get('ANALYZE_FILE_PATH', ''),
            'analyze_output': config.get('ANALYZE_OUTPUT', ''),
            'hypothesis_file_path': config.get('HYPOTHESIS_FILE_PATH', ''),
            'hypothesis_output': config.get('HYPOTHESIS_OUTPUT', ''),
            'pcap_file_path': config.get('PCAP_FILE_PATH', ''),
            'pcap_output': config.get('PCAP_OUTPUT', ''),
            'pcap_alerts_path': config.get('PCAP_ALERTS_PATH', ''),
            'rule_output': config.get('RULE_OUTPUT', ''),
            'prompt_input': config.get('PROMPT_INPUT', ''),
            'use_local_model': config.get('USE_LOCAL_MODEL', False),
            'local_model_url': config.get('LOCAL_MODEL_URL', 'http://localhost:1234'),
            'supports_functions': config.get('SUPPORTS_FUNCTIONS', True),
            'ai_only': config.get('AI_ONLY', False)
        }
    else:
        # Return default values if the config file doesn't exist
        return {
            'api_key': None,  # api_key
            'theme': 'DarkGrey16',  # theme
            'analyze_file_path': '',  # analyze_file_path
            'analyze_output': '',  # analyze_output
            'hypothesis_file_path': '',  # hypothesis_file_path
            'hypothesis_output': '',  # hypothesis_output
            'pcap_file_path': '',  # pcap_file_path
            'pcap_output': '',  # pcap_output
            'pcap_alerts_path': '',  # pcap_alerts_path
            'rule_output': '',  # rule_output
            'prompt_input': '',  # prompt_input
            'use_local_model': False,  # use_local_model
            'local_model_url': 'http://localhost:1234',  # local_model_url
            'supports_functions': True,  # supports_functions
            'ai_only': False
        }