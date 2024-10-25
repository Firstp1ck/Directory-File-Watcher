import configparser
import logging
import os

# Set up logging
logging.basicConfig(filename='app.log', filemode='w', level=logging.DEBUG, format='%(name)s - %(levelname)s - %(message)s')

config = configparser.ConfigParser()
config_file_path = r'config.ini' # relative path

# Function to validate file paths
def validate_file_path(path):
    if not os.path.exists(path):
        logging.error(f"File not found: {path}")
        raise FileNotFoundError(f"The required file does not exist: {path}")
    else:
        logging.info(f"File validated and exists: {path}")

logger = logging.getLogger(__name__)

def read_config(config_file: str) -> configparser.ConfigParser:
    """ Reads the configuration from the provided config file. """
    config = configparser.ConfigParser()
    if os.path.exists(config_file):
        logger.info(f"Reading existing config file: {config_file}")
        with open(config_file, 'r', encoding='utf-8') as f:
            config.read_file(f)
    else:
        logger.info(f"No config file found. Creating defaults at {config_file}")
    return config

def ensure_config_exists(config: configparser.ConfigParser, config_file: str):
    """ Ensure the configuration file is set with the necessary default values. """
    config_changed = False
    if not config.has_section('settings'):
        config.add_section('settings')
        config_changed = True

    if 'watch_dir' not in config['settings']:
        config.set('settings', 'watch_dir', '')
        config_changed = True

    if 'search_patterns' not in config['settings']:
        config.set('settings', 'search_patterns', '')
        config_changed = True

    if config_changed:
        with open(config_file, 'w', encoding='utf-8') as file:
            config.write(file)
        logger.info(f"Configuration defaults set in {config_file}")

if __name__ == "__main__":
    # Read and process the configuration
    try:
        if not os.path.exists(config_file_path):
            logging.error(f"Configuration file not found at {config_file_path}")
            raise FileNotFoundError(f"Configuration file not found at {config_file_path}")
        
        config.read(config_file_path)
        logging.info("Configuration file has been read successfully")

        # Retrieve paths from the config and validate each
        pdf_form = config['paths']['PDF_FORM']
        validate_file_path(pdf_form)
        print(pdf_form)

        word_form = config['paths']['WORD_FORM']
        validate_file_path(word_form)
        print(word_form)

        input_excel = config['paths']['INPUT_EXCEL']
        validate_file_path(input_excel)
        print(input_excel)

        input_db = config['paths']['INPUT_DB']
        validate_file_path(input_db)
        print(input_db)

        output = config['paths']['OUTPUT']
        validate_file_path(output)
        print(output)

    except KeyError as e:
        logging.error(f"Missing section or key in configuration file: {e}")
        raise
    except configparser.Error as e:
        logging.error(f"Error parsing the configuration file: {e}")
        raise