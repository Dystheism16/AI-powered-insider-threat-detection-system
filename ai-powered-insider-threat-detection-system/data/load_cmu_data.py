"""
CMU Insider Threat Dataset Loader

Integrates Carnegie Mellon University's Insider Threat Dataset (CMU-CTI)
into the project's data format.

Dataset: https://www.cert.org/insider-threat/tools-and-data/
Download the dataset and place it in data/cmu_dataset/

Directory structure expected:
data/cmu_dataset/
    - logins.csv
    - http.csv
    - emails.csv
    - files.csv
    - devices.csv
"""

import pandas as pd
import numpy as np
import os
from datetime import datetime

DATA_DIR = 'data'
CMU_DIR = os.path.join(DATA_DIR, 'cmu_dataset')

def load_cmu_data():
    """Load CMU dataset files."""
    if not os.path.exists(CMU_DIR):
        print(f"CMU dataset directory not found: {CMU_DIR}")
        print("Please download the CMU Insider Threat Dataset from:")
        print("https://www.cert.org/insider-threat/tools-and-data/")
        print("And extract it to data/cmu_dataset/")
        return None

    # CMU dataset file naming convention
    files = {
        'logins': os.path.join(CMU_DIR, 'logins.csv'),
        'http': os.path.join(CMU_DIR, 'http.csv'),
        'emails': os.path.join(CMU_DIR, 'emails.csv'),
        'files': os.path.join(CMU_DIR, 'file.csv'),
        'devices': os.path.join(CMU_DIR, 'device.csv')
    }

    data = {}
    for name, path in files.items():
        if os.path.exists(path):
            print(f"Loading {name}...")
            data[name] = pd.read_csv(path, low_memory=False)
        else:
            print(f"Warning: {path} not found")
            data[name] = None

    return data

def convert_cmu_logins(cmu_logins):
    """Convert CMU logins to project format."""
    if cmu_logins is None:
        return None

    df = cmu_logins.copy()
    # CMU format: user, timestamp, timestamp (login/logout in same row or separate)
    # Adjust based on actual CMU data structure
    df['timestamp'] = pd.to_datetime(df['timestamp'])

    # Split into login/logout events
    logins = df[df['activity'] == 'logon'][['user', 'timestamp']].copy()
    logouts = df[df['activity'] == 'logoff'][['user', 'timestamp']].copy()

    logins.columns = ['user', 'login']
    logouts.columns = ['user', 'logout']

    # Merge login/logout pairs
    merged = pd.merge(logins, logouts, on='user', how='left')
    return merged

def convert_cmu_http(cmu_http):
    """Convert CMU HTTP logs to file access format."""
    if cmu_http is None:
        return None

    df = cmu_http.copy()
    df['timestamp'] = pd.to_datetime(df['timestamp'])

    # Map HTTP requests to file access
    result = pd.DataFrame({
        'user': df['user'],
        'file': df['url'].apply(lambda x: x.split('/')[-1] if isinstance(x, str) else 'unknown'),
        'access_time': df['timestamp']
    })
    return result

def convert_cmu_emails(cmu_emails):
    """Convert CMU emails to project format."""
    if cmu_emails is None:
        return None

    df = cmu_emails.copy()
    df['timestamp'] = pd.to_datetime(df['timestamp'])

    result = pd.DataFrame({
        'sender': df['from'],
        'recipient': df['to'],
        'time': df['timestamp'],
        'subject': df.get('subject', 'No Subject'),
        'content': df.get('body', '')
    })
    return result

def convert_cmu_files(cmu_files):
    """Convert CMU file operations to project format."""
    if cmu_files is None:
        return None

    df = cmu_files.copy()
    df['timestamp'] = pd.to_datetime(df['timestamp'])

    # Filter for read/copy/download operations
    operations = ['read', 'copy', 'download', 'write']
    if 'operation' in df.columns:
        df = df[df['operation'].isin(operations)]

    result = pd.DataFrame({
        'user': df['user'],
        'file': df.get('file', df.get('path', 'unknown')),
        'access_time': df['timestamp']
    })
    return result

def convert_cmu_devices(cmu_devices):
    """Convert CMU device data to USB format."""
    if cmu_devices is None:
        return None

    df = cmu_devices.copy()
    df['timestamp'] = pd.to_datetime(df['timestamp'])

    # Filter for USB devices
    if 'device_type' in df.columns:
        df = df[df['device_type'].str.lower().str.contains('usb', na=False)]

    result = pd.DataFrame({
        'user': df['user'],
        'device': df.get('device_id', df.get('hardware_id', 'unknown')),
        'plug_time': df['timestamp'],
        'unplug_time': df['timestamp'] + pd.Timedelta(minutes=30)  # Estimate
    })
    return result

def save_converted_data(logins, file_access, usb_usage, emails):
    """Save converted data in project format."""
    os.makedirs(DATA_DIR, exist_ok=True)

    if logins is not None and not logins.empty:
        logins.to_csv(os.path.join(DATA_DIR, 'logins.csv'), index=False)
        print(f"Saved {len(logins)} login records")

    if file_access is not None and not file_access.empty:
        file_access.to_csv(os.path.join(DATA_DIR, 'file_access.csv'), index=False)
        print(f"Saved {len(file_access)} file access records")

    if usb_usage is not None and not usb_usage.empty:
        usb_usage.to_csv(os.path.join(DATA_DIR, 'usb_usage.csv'), index=False)
        print(f"Saved {len(usb_usage)} USB usage records")

    if emails is not None and not emails.empty:
        emails.to_csv(os.path.join(DATA_DIR, 'emails.csv'), index=False)
        print(f"Saved {len(emails)} email records")

def load_cmu_red_team():
    """Load known malicious users from CMU dataset."""
    red_team_path = os.path.join(CMU_DIR, 'red_team.csv')
    if os.path.exists(red_team_path):
        red_team = pd.read_csv(red_team_path)
        return red_team['user'].tolist()
    return []

def main():
    print("=" * 50)
    print("CMU Insider Threat Dataset Loader")
    print("=" * 50)

    # Load raw CMU data
    cmu_data = load_cmu_data()

    if cmu_data is None:
        print("\nFalling back to simulated data...")
        return False

    # Convert to project format
    print("\nConverting CMU data to project format...")

    # Try different conversion paths based on available data
    if cmu_data.get('logins') is not None:
        logins = convert_cmu_logins(cmu_data['logins'])
    else:
        logins = None

    if cmu_data.get('files') is not None:
        file_access = convert_cmu_files(cmu_data['files'])
    elif cmu_data.get('http') is not None:
        file_access = convert_cmu_http(cmu_data['http'])
    else:
        file_access = None

    if cmu_data.get('devices') is not None:
        usb_usage = convert_cmu_devices(cmu_data['devices'])
    else:
        usb_usage = None

    if cmu_data.get('emails') is not None:
        emails = convert_cmu_emails(cmu_data['emails'])
    else:
        emails = None

    # Save converted data
    save_converted_data(logins, file_access, usb_usage, emails)

    # Save red team info if available
    red_team = load_cmu_red_team()
    if red_team:
        pd.DataFrame({'user': red_team}).to_csv(
            os.path.join(DATA_DIR, 'red_team_users.csv'), index=False
        )
        print(f"Identified {len(red_team)} known malicious users from CMU dataset")

    print("\nCMU data integration complete!")
    print("You can now run the standard pipeline:")
    print("  python features/merge_features.py")
    print("  python models/train.py")
    print("  streamlit run dashboard/combined_dashboard.py")

    return True

if __name__ == '__main__':
    main()
