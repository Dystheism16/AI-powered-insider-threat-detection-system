"""
Red Team Behavior Simulator

Injects realistic malicious behaviors into the logs to test detection capability.
Now works with the new risk profile system.
"""

import pandas as pd
import numpy as np
import random
import os
from datetime import timedelta

DATA_DIR = 'data'
random.seed(99)
np.random.seed(99)

print("=" * 50)
print("Red Team Behavior Injection")
print("=" * 50)

# Load existing logs with error handling for corrupted data
print("Loading existing logs...")

# Load and clean logins
logins = pd.read_csv(os.path.join(DATA_DIR, 'logins.csv'))
logins['login'] = pd.to_datetime(logins['login'], errors='coerce')
logins['logout'] = pd.to_datetime(logins['logout'], errors='coerce')
logins = logins.dropna(subset=['login', 'user']).copy()
print(f"  Loaded {len(logins)} valid login records (cleaned)")

# Load and clean file access
file_access = pd.read_csv(os.path.join(DATA_DIR, 'file_access.csv'))
file_access['access_time'] = pd.to_datetime(file_access['access_time'], errors='coerce')
file_access = file_access.dropna(subset=['access_time', 'user', 'file']).copy()
print(f"  Loaded {len(file_access)} valid file access records (cleaned)")

# Load and clean USB usage
usb_usage = pd.read_csv(os.path.join(DATA_DIR, 'usb_usage.csv'))
usb_usage['plug_time'] = pd.to_datetime(usb_usage['plug_time'], errors='coerce')
usb_usage['unplug_time'] = pd.to_datetime(usb_usage['unplug_time'], errors='coerce')
usb_usage = usb_usage.dropna(subset=['plug_time', 'user']).copy()
print(f"  Loaded {len(usb_usage)} valid USB records (cleaned)")

# Load and clean emails
emails = pd.read_csv(os.path.join(DATA_DIR, 'emails.csv'))
emails['time'] = pd.to_datetime(emails['time'], errors='coerce')
emails = emails.dropna(subset=['time', 'sender']).copy()
print(f"  Loaded {len(emails)} valid email records (cleaned)")

# Load user profiles if available
try:
    user_profiles = pd.read_csv(os.path.join(DATA_DIR, 'user_profiles.csv'))
    print(f"Loaded {len(user_profiles)} user profiles")
except FileNotFoundError:
    user_profiles = None
    print("No user profiles found, using login data only")

users = logins['user'].unique()

# Select red team members from HIGH risk users if available, otherwise random
# Also create HOLDOUT users (unknown labels for blind evaluation)
if user_profiles is not None and 'risk_profile' in user_profiles.columns:
    high_risk_users = user_profiles[user_profiles['risk_profile'] == 'high']['user_id'].tolist()
    if high_risk_users:
        # Select 3-4 from high risk users as red team
        num_red = min(4, len(high_risk_users))
        red_users = random.sample(high_risk_users, num_red)
        # Remaining high risk users become holdout (unknown)
        holdout_users = [u for u in high_risk_users if u not in red_users]
        print(f"\nSelected {num_red} red team members from HIGH risk pool: {red_users}")
        print(f"Holdout users (unknown labels): {holdout_users}")
    else:
        num_red = min(4, max(3, len(users) // 5))
        red_users = random.sample(list(users), num_red)
        holdout_users = [u for u in users if u not in red_users][:2]
        print(f"\nSelected {num_red} red team members: {red_users}")
else:
    num_red = min(4, max(3, len(users) // 5))
    red_users = random.sample(list(users), num_red)
    holdout_users = [u for u in users if u not in red_users][:2]
    print(f"\nSelected {num_red} red team members: {red_users}")

print(f"\n🔍 BLIND EVALUATION MODE:")
print(f"   - Red Team (known threats): {len(red_users)} users")
print(f"   - Holdout (unknown labels): {len(holdout_users)} users")
print(f"   - System must detect holdout users through behavior analysis alone")

# =============================================================================
# BEHAVIOR 1: After-Hours Access (2 AM - 5 AM)
# =============================================================================
print("\n[1/5] Injecting after-hours file access...")
for user in red_users:
    for _ in range(8):
        day = random.choice(pd.date_range(file_access['access_time'].min(), file_access['access_time'].max()))
        access_time = day.replace(hour=random.randint(2, 5), minute=random.randint(0, 59))
        file = random.choice(file_access['file'].unique())

        file_access = pd.concat([
            file_access,
            pd.DataFrame([{'user': user, 'file': file, 'access_time': access_time,
                          'access_type': 'copy', 'file_size_kb': random.randint(1000, 50000)}])
        ], ignore_index=True)

print(f"  Added {8 * len(red_users)} after-hours access events")

# =============================================================================
# BEHAVIOR 2: Mass File Downloads
# =============================================================================
print("\n[2/5] Injecting mass file download behavior...")
for user in red_users:
    for _ in range(random.randint(2, 3)):
        day = random.choice(pd.date_range(file_access['access_time'].min(), file_access['access_time'].max()))
        num_files = random.randint(30, 50)
        files_to_access = random.sample(list(file_access['file'].unique()), min(num_files, len(file_access['file'].unique())))

        base_time = day.replace(hour=10, minute=random.randint(0, 59))

        for i, file in enumerate(files_to_access):
            access_time = base_time + timedelta(minutes=i * 2)
            file_access = pd.concat([
                file_access,
                pd.DataFrame([{'user': user, 'file': file, 'access_time': access_time,
                              'access_type': random.choice(['copy', 'download']),
                              'file_size_kb': random.randint(5000, 100000)}])
            ], ignore_index=True)

print(f"  Added mass download sessions for {len(red_users)} users")

# =============================================================================
# BEHAVIOR 3: Confidential File Access
# =============================================================================
print("\n[3/5] Injecting unauthorized confidential file access...")
confidential_files = [f for f in file_access['file'].unique() if 'Confidential' in f or 'confidential' in f.lower()]

if not confidential_files:
    confidential_files = [
        'Confidential/salary_data.xlsx',
        'Confidential/merger_plans.pdf',
        'Confidential/layoffs.docx',
        'Confidential/security_audit.pdf'
    ]
    for cf in confidential_files:
        file_access = pd.concat([
            file_access,
            pd.DataFrame([{'user': random.choice(users), 'file': cf,
                          'access_time': file_access['access_time'].max(),
                          'access_type': 'read', 'file_size_kb': 5000}])
        ], ignore_index=True)

for user in red_users:
    for _ in range(5):
        day = random.choice(pd.date_range(file_access['access_time'].min(), file_access['access_time'].max()))
        access_time = day.replace(hour=random.randint(9, 16), minute=random.randint(0, 59))
        file = random.choice(confidential_files)

        file_access = pd.concat([
            file_access,
            pd.DataFrame([{'user': user, 'file': file, 'access_time': access_time,
                          'access_type': random.choice(['read', 'copy', 'download']),
                          'file_size_kb': random.randint(10000, 100000)}])
        ], ignore_index=True)

print(f"  Added {5 * len(red_users)} confidential file access events")

# =============================================================================
# BEHAVIOR 4: Suspicious USB Usage (Large Data Transfers)
# =============================================================================
print("\n[4/5] Injecting suspicious USB usage...")
for user in red_users:
    for _ in range(4):
        day = random.choice(pd.date_range(usb_usage['plug_time'].min(), usb_usage['plug_time'].max()))
        hour = random.choice([6, 7, 20, 21, 22, 23])
        plug_time = day.replace(hour=hour, minute=random.randint(0, 59))
        duration = random.randint(60, 180)
        unplug_time = plug_time + timedelta(minutes=duration)
        device = random.choice(['usb_drive_01', 'external_hdd_01', 'external_hdd_02'])

        usb_usage = pd.concat([
            usb_usage,
            pd.DataFrame([{'user': user, 'device_id': device,
                          'device_type': 'External Storage',
                          'plug_time': plug_time, 'unplug_time': unplug_time,
                          'data_transferred_mb': round(random.uniform(500, 5000), 2)}])
        ], ignore_index=True)

print(f"  Added {4 * len(red_users)} suspicious USB events")

# =============================================================================
# BEHAVIOR 5: Suspicious Email Patterns
# =============================================================================
print("\n[5/5] Injecting suspicious email patterns...")
for user in red_users:
    for _ in range(6):
        day = random.choice(pd.date_range(emails['time'].min(), emails['time'].max()))
        email_time = day.replace(hour=random.randint(20, 23), minute=random.randint(0, 59))

        subject = random.choice([
            'Confidential - Do Not Forward',
            'Urgent: Wire Transfer Needed',
            'Sensitive Employee Data',
            'Off-the-record Discussion'
        ])

        emails = pd.concat([
            emails,
            pd.DataFrame([{'sender': f"{user}@company.com",
                          'recipient': f"{user}_personal@gmail.com",
                          'time': email_time,
                          'subject': subject,
                          'has_attachment': True,
                          'word_count': random.randint(50, 200)}])
        ], ignore_index=True)

print(f"  Added {6 * len(red_users)} suspicious emails")

# =============================================================================
# SAVE MODIFIED DATA (with limits to prevent clutter)
# =============================================================================
print("\nSaving modified logs...")

# Limit file_access to 500 records (keep red team injections but trim normal)
file_access = file_access.drop_duplicates(subset=['user', 'file', 'access_time'])
file_access = file_access.tail(500)

# Limit USB usage to 100 records
usb_usage = usb_usage.drop_duplicates(subset=['user', 'device_id', 'plug_time'])
usb_usage = usb_usage.tail(100)

# Limit emails to 250 records
emails = emails.drop_duplicates(subset=['sender', 'recipient', 'time', 'subject'])
emails = emails.tail(250)

file_access.to_csv(os.path.join(DATA_DIR, 'file_access.csv'), index=False)
usb_usage.to_csv(os.path.join(DATA_DIR, 'usb_usage.csv'), index=False)
emails.to_csv(os.path.join(DATA_DIR, 'emails.csv'), index=False)

print(f"\nFinal record counts (after limiting):")
print(f"  File Access: {len(file_access)} records")
print(f"  USB Usage: {len(usb_usage)} records")
print(f"  Emails: {len(emails)} records")

# Save red team member list with risk info
red_team_df = pd.DataFrame({
    'user': red_users,
    'threat_type': ['data_exfil'] * len(red_users),
    'injection_date': pd.Timestamp.now(),
    'is_red_team': [1] * len(red_users),
    'label_known': ['yes'] * len(red_users)
})
red_team_df.to_csv(os.path.join(DATA_DIR, 'red_team_users.csv'), index=False)

# Save holdout users (unknown labels for blind evaluation)
if holdout_users:
    holdout_df = pd.DataFrame({
        'user': holdout_users,
        'label_known': ['no'] * len(holdout_users),
        'note': 'Holdout for blind evaluation - system must detect through behavior'
    })
    holdout_df.to_csv(os.path.join(DATA_DIR, 'holdout_users.csv'), index=False)
    print(f"\n📁 Holdout users saved to data/holdout_users.csv")

print("\n" + "=" * 50)
print("Red Team Injection Complete!")
print("=" * 50)
print(f"\nRed Team Members ({len(red_users)}):")
for u in red_users:
    print(f"  - {u}")
print("\nInjected Behaviors:")
print("  ✓ After-hours file access (2-5 AM)")
print("  ✓ Mass file download sessions")
print("  ✓ Confidential file access")
print("  ✓ Suspicious USB usage (large transfers)")
print("  ✓ External email communications")
print("\nData saved to data/ directory")
