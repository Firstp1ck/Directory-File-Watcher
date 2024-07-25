import os
import configparser
import pandas as pd
import bcrypt
import matplotlib.pyplot as plt
from datetime import datetime

# Load configuration
config = configparser.ConfigParser()
config.read(r'src\config.ini')

LOG_STORAGE = config['TRACKING']['log_storage']
LOG_FILE = os.path.join(LOG_STORAGE, 'excel_usage_log.csv')
OUTPUT_FOLDER = config['ANALYSIS']['output_folder']

# Ensure output directory exists
os.makedirs(OUTPUT_FOLDER, exist_ok=True)

def load_log_file(log_file: str) -> pd.DataFrame:
    """
    Load log data from CSV file into a pandas DataFrame.
    """
    try:
        log_df = pd.read_csv(log_file, names=['timestamp', 'user', 'event_type', 'file_path'])
        log_df['timestamp'] = pd.to_datetime(log_df['timestamp'])
        return log_df
    except Exception as e:
        print(f"Error while loading log file: {e}")
        return pd.DataFrame()

def perform_basic_analysis(log_df: pd.DataFrame):
    """
    Perform basic analysis on log data and save reports/graphs.
    """
    # Total events
    total_events = log_df['event_type'].value_counts()
    total_events.plot(kind='bar', title='Total Events per Event Type')
    plt.savefig(os.path.join(OUTPUT_FOLDER, 'total_events.png'))
    plt.close()

    # Events over time
    log_df.set_index('timestamp', inplace=True)
    events_over_time = log_df['event_type'].resample('D').count()
    events_over_time.plot(title='Events Over Time')
    plt.savefig(os.path.join(OUTPUT_FOLDER, 'events_over_time.png'))
    plt.close()

    # Most active users (Placeholder decoding function used)
    active_users = log_df['user'].value_counts()
    active_users.plot(kind='bar', title='Most Active Users')
    plt.savefig(os.path.join(OUTPUT_FOLDER, 'most_active_users.png'))
    plt.close()

def main():
    # Load log data
    log_df = load_log_file(LOG_FILE)
    if log_df.empty:
        print("No log data available to analyze.")
        return

    # Perform analysis
    perform_basic_analysis(log_df)
    print(f"Analysis completed. Output saved to {OUTPUT_FOLDER}")

if __name__ == "__main__":
    main()