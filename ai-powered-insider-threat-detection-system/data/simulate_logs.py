"""
Enhanced Log Simulator for Insider Threat Detection

Generates realistic synthetic logs with diverse user behaviors,
multiple risk profiles, and balanced data distribution.
"""

import os
import random
import pandas as pd
import numpy as np
from datetime import datetime, timedelta

# Configuration - Realistic production-like settings
NUM_USERS = 30  # Users
DAYS = 60  # 2 months of data
START_DATE = datetime(2024, 1, 2)  # Start from a Monday
SEED = 42

# Realistic messiness parameters
CORRUPTION_RATE = 0.015  # 1.5% of records will be corrupted
DUPLICATE_RATE = 0.008  # 0.8% duplicates
SYSTEM_OUTAGE_DAYS = [15, 32, 47]  # Days with partial/missing data
TERMINATED_USERS = []  # Users who leave mid-period (set dynamically)
TIMEZONE_OFFSETS = [-5, -4, -3, 0, 1, 2, 5.5]  # Various timezone offsets in hours

random.seed(SEED)
np.random.seed(SEED)

# Create data directory
os.makedirs('data', exist_ok=True)

DEPARTMENTS = ['Engineering', 'Finance', 'HR', 'Marketing', 'Sales', 'IT', 'Legal', 'Operations']

JOB_ROLES = {
    'Engineering': ['Software Engineer', 'Senior Developer', 'DevOps Engineer', 'QA Analyst', 'Intern'],
    'Finance': ['Accountant', 'Financial Analyst', 'Controller', 'Intern'],
    'HR': ['HR Manager', 'Recruiter', 'HR Coordinator'],
    'Marketing': ['Marketing Manager', 'Content Specialist', 'Social Media Manager'],
    'Sales': ['Sales Rep', 'Account Manager', 'Sales Director'],
    'IT': ['System Admin', 'Network Engineer', 'Security Analyst', 'Help Desk'],
    'Legal': ['Legal Counsel', 'Compliance Officer', 'Paralegal'],
    'Operations': ['Operations Manager', 'Logistics Coordinator', 'Analyst']
}

WORK_PATTERNS = {
    'Software Engineer': (8, 19, 2),
    'Senior Developer': (9, 20, 2),
    'DevOps Engineer': (7, 18, 3),
    'QA Analyst': (9, 18, 1),
    'Intern': (9, 17, 0),
    'Accountant': (8, 17, 1),
    'Financial Analyst': (8, 18, 1),
    'Controller': (7, 17, 1),
    'HR Manager': (8, 17, 1),
    'Recruiter': (9, 18, 2),
    'HR Coordinator': (9, 17, 0),
    'Marketing Manager': (9, 18, 2),
    'Content Specialist': (10, 19, 2),
    'Social Media Manager': (11, 20, 2),
    'Sales Rep': (8, 18, 3),
    'Account Manager': (8, 18, 2),
    'Sales Director': (7, 19, 3),
    'System Admin': (6, 17, 4),
    'Network Engineer': (7, 18, 3),
    'Security Analyst': (8, 18, 2),
    'Help Desk': (7, 20, 2),
    'Legal Counsel': (8, 19, 2),
    'Compliance Officer': (8, 17, 1),
    'Paralegal': (8, 18, 1),
    'Operations Manager': (7, 18, 2),
    'Logistics Coordinator': (6, 16, 1),
    'Analyst': (9, 18, 1)
}

RISK_PROFILES = {
    'low': {
        'weight': 0.60,
        'after_hours_prob': 0.02,
        'file_access_range': (2, 5),
        'usb_usage_prob': 0.05,
        'email_range': (3, 8),
        'confidential_access_prob': 0.01,
        'large_transfer_prob': 0.01
    },
    'medium': {
        'weight': 0.27,
        'after_hours_prob': 0.08,
        'file_access_range': (5, 12),
        'usb_usage_prob': 0.15,
        'email_range': (6, 15),
        'confidential_access_prob': 0.05,
        'large_transfer_prob': 0.05
    },
    'high': {
        'weight': 0.13,
        'after_hours_prob': 0.25,
        'file_access_range': (10, 20),
        'usb_usage_prob': 0.35,
        'email_range': (10, 25),
        'confidential_access_prob': 0.15,
        'large_transfer_prob': 0.20
    }
}

def generate_user_profiles():
    """Generate user profiles with realistic messiness."""
    users = []
    n_low = int(NUM_USERS * RISK_PROFILES['low']['weight'])
    n_medium = int(NUM_USERS * RISK_PROFILES['medium']['weight'])
    n_high = NUM_USERS - n_low - n_medium

    risk_assignments = ['low'] * n_low + ['medium'] * n_medium + ['high'] * n_high
    random.shuffle(risk_assignments)

    # Select 2-3 users who will be "terminated" mid-period
    global TERMINATED_USERS
    TERMINATED_USERS = random.sample([f'user{i}' for i in range(1, NUM_USERS + 1)], k=3)
    termination_dates = {u: START_DATE + timedelta(days=random.randint(20, 45))
                         for u in TERMINATED_USERS}

    for i in range(1, NUM_USERS + 1):
        dept = random.choice(DEPARTMENTS)
        role = random.choice(JOB_ROLES[dept])
        work_pattern = WORK_PATTERNS[role]
        risk = risk_assignments[i - 1]
        user_id = f'user{i}'

        # Random timezone offset for each user
        tz_offset = random.choice(TIMEZONE_OFFSETS)

        user_data = {
            'user_id': user_id,
            'email': f'user{i}@company.com',
            'department': dept,
            'role': role,
            'work_start': work_pattern[0],
            'work_end': work_pattern[1],
            'flexibility': work_pattern[2],
            'risk_profile': risk,
            'timezone_offset': tz_offset,
            'terminated': user_id in TERMINATED_USERS,
            'termination_date': termination_dates.get(user_id, None)
        }
        users.append(user_data)

    return pd.DataFrame(users)

FILE_TYPES = {
    'Engineering': ['spec.docx', 'design.pdf', 'code.py', 'test.java'],
    'Finance': ['budget.xlsx', 'report.xlsx', 'invoice.pdf', 'forecast.xlsx'],
    'HR': ['resume.pdf', 'policy.docx', 'review.xlsx', 'contract.docx'],
    'Marketing': ['campaign.pptx', 'brief.docx', 'analytics.xlsx', 'content.docx'],
    'Sales': ['proposal.docx', 'contract.pdf', 'pipeline.xlsx', 'quote.xlsx'],
    'IT': ['config.yaml', 'script.sh', 'documentation.md', 'incident.docx'],
    'Legal': ['brief.docx', 'contract.pdf', 'memo.docx', 'case.pdf'],
    'Operations': ['report.xlsx', 'schedule.xlsx', 'process.docx', 'metrics.xlsx']
}

SHARED_FILES = ['company_policy.pdf', 'org_chart.xlsx', 'meeting_notes.docx', 'project_plan.xlsx']

CONFIDENTIAL_FILES = ['salary_data.xlsx', 'performance_reviews.docx', 'merger_plans.pdf', 'security_audit.pdf']

def generate_files():
    files = []
    for dept in DEPARTMENTS:
        for file_type in FILE_TYPES[dept]:
            for j in range(1, 3):
                files.append(f"{dept}/{file_type.replace('.', '_')}_{j}.{file_type.split('.')[-1]}")
    for f in SHARED_FILES:
        files.append(f"Shared/{f}")
    for f in CONFIDENTIAL_FILES:
        files.append(f"Confidential/{f}")
    return files

USB_DEVICES = [
    ('usb_drive_01', 'SanDisk 32GB'), ('usb_drive_02', 'Kingston 64GB'),
    ('usb_drive_03', 'Samsung 128GB'), ('usb_drive_04', 'SanDisk 16GB'),
    ('external_hdd_01', 'WD 1TB'), ('external_hdd_02', 'Seagate 2TB'),
    ('phone_android_01', 'Samsung Galaxy'), ('phone_iphone_01', 'iPhone 14'),
]

NORMAL_SUBJECTS = [
    'Team Meeting Tomorrow', 'Project Update', 'Quick Question', 'Weekly Report',
    'Status Update', 'Re: Your Email', 'Follow-up', 'Document Review',
    'Feedback Requested', 'Action Required', 'FYI', 'Schedule Change',
    'Office Update', 'New Hire Orientation', 'Training Session', 'Budget Review',
    'Client Call Notes', 'Sprint Review', 'Code Review Request', 'Bug Report',
]

SUSPICIOUS_SUBJECTS = [
    'Confidential - Do Not Forward', 'Urgent: Wire Transfer Needed',
    'Sensitive: Employee Data', 'Private - Management Only',
]

def simulate_logins(users_df):
    """Generate login records with realistic messiness."""
    records = []
    for day_offset in range(DAYS):
        current_date = START_DATE + timedelta(days=day_offset)

        # System outage - no/partial data on certain days
        if day_offset in SYSTEM_OUTAGE_DAYS:
            if random.random() < 0.7:  # 70% chance of complete outage
                continue
            # Partial data - only 30% of normal records
            users_to_process = users_df.sample(frac=0.3)
        else:
            users_to_process = users_df

        if current_date.weekday() >= 5 and random.random() < 0.85:
            continue

        for _, user in users_to_process.iterrows():
            # Skip terminated users after their termination date
            if user['terminated'] and current_date >= user['termination_date']:
                continue

            if random.random() < 0.05:
                continue

            work_start = user['work_start']
            work_end = user['work_end']
            flexibility = user['flexibility']
            tz_offset = user.get('timezone_offset', 0)
            actual_start = max(6, min(22, work_start + random.randint(-flexibility, flexibility)))
            login_hour = actual_start + random.random() * 2

            if user['risk_profile'] == 'high' and random.random() < 0.3:
                login_hour = random.choice([4, 5, 6, 22, 23, 0, 1])

            login_time = current_date.replace(hour=int(login_hour), minute=random.randint(0, 59), second=random.randint(0, 59))
            logout_time = login_time + timedelta(hours=random.randint(7, 10))

            records.append({
                'user': user['user_id'],
                'department': user['department'],
                'login': login_time,
                'logout': logout_time,
                'day_of_week': current_date.strftime('%A'),
                'timezone_offset': tz_offset
            })

    df = pd.DataFrame(records)

    # Add duplicates
    num_duplicates = int(len(df) * DUPLICATE_RATE)
    if num_duplicates > 0 and len(df) > 0:
        dupes = df.sample(n=num_duplicates, replace=True)
        df = pd.concat([df, dupes], ignore_index=True)

    # Add corrupted records
    num_corrupted = int(len(df) * CORRUPTION_RATE)
    for _ in range(num_corrupted):
        idx = random.randint(0, len(df) - 1)
        record = df.iloc[idx].to_dict()
        # Corrupt in various ways
        corruption_type = random.choice(['null', 'invalid_date', 'negative', 'garbage'])
        if corruption_type == 'null':
            field = random.choice(['login', 'logout', 'user'])
            record[field] = None
        elif corruption_type == 'invalid_date':
            record['login'] = 'invalid-date'
        elif corruption_type == 'negative':
            record['logout'] = -999
        elif corruption_type == 'garbage':
            record['user'] = '###CORRUPTED###'
        df = pd.concat([df, pd.DataFrame([record])], ignore_index=True)

    df.to_csv('data/logins.csv', index=False)
    print(f"Generated {len(df)} login records (including {num_duplicates} duplicates, {num_corrupted} corrupted)")
    return df

def simulate_file_access(users_df, files_list, max_records=500):
    """Generate file access records with realistic messiness."""
    records = []
    confidential = [f for f in files_list if 'Confidential' in f]
    normal_files = [f for f in files_list if 'Confidential' not in f]
    user_ids = list(users_df['user_id'])

    while len(records) < max_records:
        day_offset = random.randint(0, DAYS - 1)

        # System outage
        if day_offset in SYSTEM_OUTAGE_DAYS and random.random() < 0.7:
            continue

        current_date = START_DATE + timedelta(days=day_offset)
        if current_date.weekday() >= 5 and random.random() < 0.85:
            continue

        user_id = random.choice(user_ids)
        user = users_df[users_df['user_id'] == user_id].iloc[0]

        # Skip terminated users
        if user['terminated'] and current_date >= user['termination_date']:
            continue

        risk = RISK_PROFILES[user['risk_profile']]

        if random.random() < 0.7:
            dept_files = [f for f in normal_files if user['department'] in f]
            file = random.choice(dept_files) if dept_files else random.choice(normal_files)
        else:
            file = random.choice(normal_files)

        if random.random() < risk['after_hours_prob']:
            hour = random.choice([2, 3, 4, 5, 21, 22, 23, 0, 1])
        else:
            hour = random.randint(max(6, user['work_start'] - 2), min(20, user['work_end'] + 2))

        access_time = current_date.replace(hour=hour, minute=random.randint(0, 59), second=random.randint(0, 59))
        access_type = random.choice(['copy', 'download', 'read']) if user['risk_profile'] == 'high' and random.random() < 0.4 else random.choice(['read', 'read', 'read', 'write', 'copy'])

        records.append({
            'user': user['user_id'], 'file': file, 'access_time': access_time,
            'access_type': access_type, 'file_size_kb': random.randint(10, 50000)
        })

    records = records[:max_records]
    df = pd.DataFrame(records)

    # Add duplicates
    num_duplicates = int(len(df) * DUPLICATE_RATE)
    if num_duplicates > 0 and len(df) > 0:
        dupes = df.sample(n=num_duplicates, replace=True)
        df = pd.concat([df, dupes], ignore_index=True)

    # Add corrupted records
    num_corrupted = int(len(df) * CORRUPTION_RATE)
    for _ in range(num_corrupted):
        idx = random.randint(0, len(df) - 1)
        record = df.iloc[idx].to_dict()
        corruption_type = random.choice(['null', 'invalid_date', 'negative', 'garbage'])
        if corruption_type == 'null':
            record['file'] = None
        elif corruption_type == 'invalid_date':
            record['access_time'] = 'corrupted'
        elif corruption_type == 'negative':
            record['file_size_kb'] = -1
        elif corruption_type == 'garbage':
            record['file'] = '###DELETED###'
        df = pd.concat([df, pd.DataFrame([record])], ignore_index=True)

    df.to_csv('data/file_access.csv', index=False)
    print(f"Generated {len(df)} file access records (including {num_duplicates} duplicates, {num_corrupted} corrupted)")
    return df

def simulate_usb_usage(users_df, max_records=100):
    """Generate USB usage records with realistic messiness."""
    records = []
    user_ids = list(users_df['user_id'])

    while len(records) < max_records:
        day_offset = random.randint(0, DAYS - 1)

        # System outage
        if day_offset in SYSTEM_OUTAGE_DAYS and random.random() < 0.7:
            continue

        current_date = START_DATE + timedelta(days=day_offset)
        if current_date.weekday() >= 5 and random.random() < 0.85:
            continue

        user_id = random.choice(user_ids)
        user = users_df[users_df['user_id'] == user_id].iloc[0]

        # Skip terminated users
        if user['terminated'] and current_date >= user['termination_date']:
            continue

        risk = RISK_PROFILES[user['risk_profile']]
        device = random.choice(USB_DEVICES)

        if user['risk_profile'] == 'high' and random.random() < risk['after_hours_prob']:
            hour = random.choice([2, 3, 4, 5, 21, 22, 23])
        else:
            hour = random.randint(user['work_start'], min(user['work_end'], 17))

        plug_time = current_date.replace(hour=hour, minute=random.randint(0, 59), second=random.randint(0, 59))
        duration = random.randint(5, 120)
        unplug_time = plug_time + timedelta(minutes=duration)
        data_mb = round(random.uniform(100, 5000), 2) if user['risk_profile'] == 'high' else round(random.uniform(10, 500), 2)

        records.append({
            'user': user_id, 'device_id': device[0], 'device_type': device[1],
            'plug_time': plug_time, 'unplug_time': unplug_time, 'data_transferred_mb': data_mb
        })

    records = records[:max_records]
    df = pd.DataFrame(records)

    # Add duplicates
    num_duplicates = int(len(df) * DUPLICATE_RATE)
    if num_duplicates > 0 and len(df) > 0:
        dupes = df.sample(n=num_duplicates, replace=True)
        df = pd.concat([df, dupes], ignore_index=True)

    # Add corrupted records
    num_corrupted = int(len(df) * CORRUPTION_RATE)
    for _ in range(num_corrupted):
        idx = random.randint(0, len(df) - 1)
        record = df.iloc[idx].to_dict()
        corruption_type = random.choice(['null', 'invalid_date', 'negative', 'garbage'])
        if corruption_type == 'null':
            record['device_id'] = None
        elif corruption_type == 'invalid_date':
            record['plug_time'] = 'invalid'
        elif corruption_type == 'negative':
            record['data_transferred_mb'] = -500
        elif corruption_type == 'garbage':
            record['device_type'] = '###UNKNOWN###'
        df = pd.concat([df, pd.DataFrame([record])], ignore_index=True)

    df.to_csv('data/usb_usage.csv', index=False)
    print(f"Generated {len(df)} USB usage records (including {num_duplicates} duplicates, {num_corrupted} corrupted)")
    return df

def simulate_emails(users_df, max_records=250):
    """Generate email records with realistic messiness."""
    records = []
    user_ids = list(users_df['user_id'])

    while len(records) < max_records:
        day_offset = random.randint(0, DAYS - 1)

        # System outage
        if day_offset in SYSTEM_OUTAGE_DAYS and random.random() < 0.7:
            continue

        current_date = START_DATE + timedelta(days=day_offset)
        if current_date.weekday() >= 5 and random.random() < 0.85:
            continue

        sender = random.choice(user_ids)
        sender_row = users_df[users_df['user_id'] == sender].iloc[0]

        # Skip terminated users
        if sender_row['terminated'] and current_date >= sender_row['termination_date']:
            continue

        sender_dept = sender_row['department']
        risk = RISK_PROFILES[sender_row['risk_profile']]

        num_recipients = random.randint(1, 3)
        possible_recipients = [u for u in user_ids if u != sender]
        same_dept = users_df[users_df['department'] == sender_dept]['user_id'].tolist()
        other_dept = [u for u in possible_recipients if u not in same_dept]

        recipients = []
        if same_dept and random.random() < 0.7:
            recipients.extend(random.sample(same_dept, min(num_recipients, len(same_dept))))
        if len(recipients) < num_recipients and other_dept:
            remaining = num_recipients - len(recipients)
            recipients.extend(random.sample(other_dept, min(remaining, len(other_dept))))

        recipient = recipients[0] if recipients else random.choice(possible_recipients)

        if sender_row['risk_profile'] == 'high' and random.random() < 0.15:
            hour = random.choice([22, 23, 0, 1, 2, 3])
        else:
            hour = random.randint(7, 19)

        email_time = current_date.replace(hour=hour, minute=random.randint(0, 59), second=random.randint(0, 59))
        subject = random.choice(SUSPICIOUS_SUBJECTS) if random.random() < risk['confidential_access_prob'] * 2 else random.choice(NORMAL_SUBJECTS)

        records.append({
            'sender': f"{sender}@company.com", 'recipient': f"{recipient}@company.com",
            'time': email_time, 'subject': subject,
            'has_attachment': random.choice([True, False, False, False]), 'word_count': random.randint(10, 500)
        })

    records = records[:max_records]
    df = pd.DataFrame(records)

    # Add duplicates
    num_duplicates = int(len(df) * DUPLICATE_RATE)
    if num_duplicates > 0 and len(df) > 0:
        dupes = df.sample(n=num_duplicates, replace=True)
        df = pd.concat([df, dupes], ignore_index=True)

    # Add corrupted records
    num_corrupted = int(len(df) * CORRUPTION_RATE)
    for _ in range(num_corrupted):
        idx = random.randint(0, len(df) - 1)
        record = df.iloc[idx].to_dict()
        corruption_type = random.choice(['null', 'invalid_date', 'negative', 'garbage'])
        if corruption_type == 'null':
            record['subject'] = None
        elif corruption_type == 'invalid_date':
            record['time'] = 'corrupted'
        elif corruption_type == 'negative':
            record['word_count'] = -100
        elif corruption_type == 'garbage':
            record['sender'] = '###DELETED###@company.com'
        df = pd.concat([df, pd.DataFrame([record])], ignore_index=True)

    df.to_csv('data/emails.csv', index=False)
    print(f"Generated {len(df)} email records (including {num_duplicates} duplicates, {num_corrupted} corrupted)")
    return df

def save_user_profiles(users_df):
    users_df.to_csv('data/user_profiles.csv', index=False)
    risk_counts = users_df['risk_profile'].value_counts()
    print(f"\nUser Risk Profile Distribution:")
    for risk, count in risk_counts.items():
        print(f"  {risk.upper()}: {count} users ({count/len(users_df)*100:.1f}%)")
    print(f"\nSaved {len(users_df)} user profiles")

def main():
    print("=" * 60)
    print("Enhanced Log Simulator - Insider Threat Detection")
    print("=" * 60)
    print(f"Generating {DAYS} days of data for {NUM_USERS} users...")
    print()

    users_df = generate_user_profiles()
    save_user_profiles(users_df)

    files_list = generate_files()
    print(f"Generated {len(files_list)} unique files")

    print("\nSimulating logs...")
    simulate_logins(users_df)
    simulate_file_access(users_df, files_list, max_records=500)
    simulate_usb_usage(users_df, max_records=100)
    simulate_emails(users_df, max_records=250)

    print("\n" + "=" * 60)
    print("Data generation complete!")
    print("=" * 60)

if __name__ == '__main__':
    main()
