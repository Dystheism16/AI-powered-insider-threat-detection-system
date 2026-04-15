"""
Real-time Data Ingestion Simulator

Simulates streaming data ingestion for the insider threat detection system.
Generates events in real-time to demonstrate live detection capability.
"""

import os
import sys
import time
import random
import pandas as pd
import argparse
from datetime import datetime, timedelta
from queue import Queue
import json
import threading

DATA_DIR = 'data'
event_queue = Queue()

# Configuration
NUM_EVENTS_PER_MINUTE = 20
SIMULATION_DURATION_SEC = 300  # 5 minutes default

def load_existing_data():
    """Load existing user profiles and reference data."""
    try:
        users = pd.read_csv(os.path.join(DATA_DIR, 'user_profiles.csv'))
        file_access = pd.read_csv(os.path.join(DATA_DIR, 'file_access.csv'))
        emails = pd.read_csv(os.path.join(DATA_DIR, 'emails.csv'))
        return users, file_access, emails
    except FileNotFoundError as e:
        print(f"Error loading data: {e}")
        print("Please run the full pipeline first: ./start.sh")
        sys.exit(1)

def generate_login_event(users):
    """Generate a realistic login event."""
    user = users.sample(1).iloc[0]
    now = datetime.now()

    # Simulate login with some randomness
    login_time = now - timedelta(seconds=random.randint(0, 3600))
    logout_time = login_time + timedelta(hours=random.randint(6, 10))

    return {
        'event_type': 'login',
        'timestamp': login_time.isoformat(),
        'user': user['user_id'],
        'department': user['department'],
        'login': login_time.isoformat(),
        'logout': logout_time.isoformat(),
        'day_of_week': now.strftime('%A')
    }

def generate_file_access_event(users, file_access):
    """Generate a file access event."""
    user = users.sample(1).iloc[0]
    files = file_access['file'].unique()

    now = datetime.now()
    access_time = now - timedelta(seconds=random.randint(0, 7200))

    return {
        'event_type': 'file_access',
        'timestamp': access_time.isoformat(),
        'user': user['user_id'],
        'file': random.choice(files),
        'access_type': random.choice(['read', 'write', 'copy', 'download']),
        'file_size_kb': random.randint(100, 50000)
    }

def generate_usb_event(users):
    """Generate a USB device usage event."""
    user = users.sample(1).iloc[0]
    now = datetime.now()
    plug_time = now - timedelta(minutes=random.randint(5, 120))

    devices = ['usb_drive_01', 'usb_drive_02', 'external_hdd_01', 'phone_android_01']

    return {
        'event_type': 'usb_usage',
        'timestamp': plug_time.isoformat(),
        'user': user['user_id'],
        'device_id': random.choice(devices),
        'device_type': 'External Storage',
        'plug_time': plug_time.isoformat(),
        'unplug_time': (plug_time + timedelta(minutes=random.randint(10, 60))).isoformat(),
        'data_transferred_mb': round(random.uniform(50, 2000), 2)
    }

def generate_email_event(users, emails):
    """Generate an email event."""
    sender = users.sample(1).iloc[0]['user_id']
    recipients = users.sample(random.randint(1, 3))['user_id'].tolist()

    if sender in recipients:
        recipients.remove(sender)

    if not recipients:
        recipients = ['external_user@gmail.com']

    now = datetime.now()
    email_time = now - timedelta(minutes=random.randint(0, 1440))

    subjects = [
        'Project Update', 'Meeting Tomorrow', 'Quick Question',
        'Confidential - Do Not Forward', 'Urgent Action Required',
        'Weekly Report', 'FYI'
    ]

    return {
        'event_type': 'email',
        'timestamp': email_time.isoformat(),
        'sender': f"{sender}@company.com",
        'recipient': f"{recipients[0]}@company.com" if 'company' in str(recipients[0]) else recipients[0],
        'subject': random.choice(subjects),
        'has_attachment': random.choice([True, False]),
        'word_count': random.randint(20, 500)
    }

def event_generator(users, file_access, emails, stop_event):
    """Continuously generate events and add to queue."""
    event_types = ['login', 'file_access', 'usb_usage', 'email']

    while not stop_event.is_set():
        event_type = random.choice(event_types)

        if event_type == 'login':
            event = generate_login_event(users)
        elif event_type == 'file_access':
            event = generate_file_access_event(users, file_access)
        elif event_type == 'usb_usage':
            event = generate_usb_event(users)
        else:
            event = generate_email_event(users, emails)

        event_queue.put(event)

        # Random delay between events (simulate real-time)
        time.sleep(random.uniform(0.5, 3.0))

def event_processor(stop_event):
    """Process events from queue and append to CSV files."""
    processed_count = {'login': 0, 'file_access': 0, 'usb_usage': 0, 'email': 0}

    while not stop_event.is_set() or not event_queue.empty():
        try:
            event = event_queue.get(timeout=1)
            event_type = event['event_type']

            # Append to appropriate CSV
            if event_type == 'login':
                df_path = os.path.join(DATA_DIR, 'logins.csv')
                if os.path.exists(df_path):
                    df = pd.read_csv(df_path)
                    new_row = pd.DataFrame([{
                        'user': event['user'],
                        'department': event['department'],
                        'login': event['login'],
                        'logout': event['logout'],
                        'day_of_week': event['day_of_week']
                    }])
                    df = pd.concat([df, new_row], ignore_index=True)
                    df.to_csv(df_path, index=False)
                processed_count['login'] += 1

            elif event_type == 'file_access':
                df_path = os.path.join(DATA_DIR, 'file_access.csv')
                if os.path.exists(df_path):
                    df = pd.read_csv(df_path)
                    new_row = pd.DataFrame([{
                        'user': event['user'],
                        'file': event['file'],
                        'access_time': event['timestamp'],
                        'access_type': event['access_type'],
                        'file_size_kb': event['file_size_kb']
                    }])
                    df = pd.concat([df, new_row], ignore_index=True)
                    df.to_csv(df_path, index=False)
                processed_count['file_access'] += 1

            elif event_type == 'usb_usage':
                df_path = os.path.join(DATA_DIR, 'usb_usage.csv')
                if os.path.exists(df_path):
                    df = pd.read_csv(df_path)
                    new_row = pd.DataFrame([{
                        'user': event['user'],
                        'device_id': event['device_id'],
                        'device_type': event['device_type'],
                        'plug_time': event['plug_time'],
                        'unplug_time': event['unplug_time'],
                        'data_transferred_mb': event['data_transferred_mb']
                    }])
                    df = pd.concat([df, new_row], ignore_index=True)
                    df.to_csv(df_path, index=False)
                processed_count['usb_usage'] += 1

            elif event_type == 'email':
                df_path = os.path.join(DATA_DIR, 'emails.csv')
                if os.path.exists(df_path):
                    df = pd.read_csv(df_path)
                    new_row = pd.DataFrame([{
                        'sender': event['sender'],
                        'recipient': event['recipient'],
                        'time': event['timestamp'],
                        'subject': event['subject'],
                        'has_attachment': event['has_attachment'],
                        'word_count': event['word_count']
                    }])
                    df = pd.concat([df, new_row], ignore_index=True)
                    df.to_csv(df_path, index=False)
                processed_count['email'] += 1

            # Print progress
            print(f"[{datetime.now().strftime('%H:%M:%S')}] Processed: {event_type} - Total: {processed_count}")

        except Exception as e:
            if 'queue' not in str(e):  # Ignore queue empty errors
                print(f"Error processing event: {e}")

    return processed_count

def main():
    parser = argparse.ArgumentParser(description='Real-time data ingestion simulator')
    parser.add_argument('--duration', type=int, default=300, help='Duration in seconds (default: 300)')
    parser.add_argument('--real-time', action='store_true', help='Run in real-time mode')
    args = parser.parse_args()

    print("=" * 60)
    print("Real-Time Data Ingestion Simulator")
    print("=" * 60)
    print(f"Duration: {args.duration} seconds")
    print(f"Mode: {'Real-time' if args.real_time else 'Fast-forward'}")
    print()

    # Load existing data
    print("Loading existing data...")
    users, file_access, emails = load_existing_data()
    print(f"Loaded {len(users)} users, {len(file_access)} file records, {len(emails)} email records")
    print()

    # Create stop event for threads
    stop_event = threading.Event()

    # Start generator thread
    generator_thread = threading.Thread(
        target=event_generator,
        args=(users, file_access, emails, stop_event),
        daemon=True
    )
    generator_thread.start()

    # Run processor in main thread
    print("Starting event processing...")
    print("Press Ctrl+C to stop")
    print()

    start_time = time.time()
    try:
        while time.time() - start_time < args.duration:
            event_processor(stop_event)
            if not args.real_time:
                time.sleep(0.1)  # Small delay in fast mode
    except KeyboardInterrupt:
        print("\nStopping simulation...")

    stop_event.set()
    time.sleep(1)  # Wait for threads to finish

    print()
    print("=" * 60)
    print("Simulation Complete!")
    print("=" * 60)

if __name__ == '__main__':
    main()
