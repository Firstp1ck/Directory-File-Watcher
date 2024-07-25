import os
import getpass
import logging
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import configparser
from datetime import datetime
import pandas as pd
from typing import Optional

# Load configuration
config = configparser.ConfigParser()
config.read(r'src\config_Analysis_DIR')

LOG_FILE = config['LOGGING']['log_file']
EXCEL_FOLDER = config['TRACKING']['excel_folder']
LOG_STORAGE = config['TRACKING']['log_storage']

# Setup logging
logging.basicConfig(filename=LOG_FILE, level=logging.INFO, format='%(asctime)s - %(message)s')

# File System Event Handler
class ExcelEventHandler(FileSystemEventHandler):
    def __init__(self, log_storage: str):
        super().__init__()
        self.log_storage = log_storage

    def on_modified(self, event):
        if event.src_path.endswith(('.xlsx', '.xlsm')):
            self.log_event('MODIFIED', event.src_path)

    def on_created(self, event):
        if event.src_path.endswith(('.xlsx', '.xlsm')):
            self.log_event('CREATED', event.src_path)

    def on_deleted(self, event):
        if event.src_path.endswith(('.xlsx', '.xlsm')):
            self.log_event('DELETED', event.src_path)

    def log_event(self, event_type: str, file_path: str):
        try:
            user = getpass.getuser()
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            log_data = {
                'timestamp': timestamp,
                'user': user,
                'event_type': event_type,
                'file_path': file_path
            }
            log_df = pd.DataFrame([log_data])
            log_df.to_csv(os.path.join(self.log_storage, 'excel_usage_log.csv'), mode='a', header=False, index=False)
            logging.info(f'{event_type} - {file_path} by {user}')
        except Exception as e:
            logging.error(f'Error logging event: {e}')

def main():
    # Ensure log storage directory exists
    os.makedirs(LOG_STORAGE, exist_ok=True)

    # Set up Watchdog observer
    event_handler = ExcelEventHandler(LOG_STORAGE)
    observer = Observer()
    # Set recursive=True to monitor all subfolders
    observer.schedule(event_handler, path=EXCEL_FOLDER, recursive=True)

    try:
        observer.start()
        print(f'Starting Excel monitoring in {EXCEL_FOLDER} and its subfolders')
        while True:
            pass  # Keeping the script running
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

if __name__ == "__main__":
    main()