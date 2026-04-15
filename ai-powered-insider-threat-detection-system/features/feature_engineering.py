"""
Enhanced Feature Engineering

Extracts behavioral features from logs including:
- Login patterns and work hour anomalies
- File access frequency and unusual access
- USB usage patterns
- Email communication patterns
- Cross-session anomalies
"""

import pandas as pd
import numpy as np
import os
from datetime import datetime

DATA_DIR = 'data'

def load_logs():
    """Load all log files with error handling for corrupted dates."""
    # Load with error coercion for corrupted dates
    logins = pd.read_csv(os.path.join(DATA_DIR, 'logins.csv'))
    logins['login'] = pd.to_datetime(logins['login'], errors='coerce')
    logins['logout'] = pd.to_datetime(logins['logout'], errors='coerce')
    logins = logins.dropna(subset=['login']).copy()

    file_access = pd.read_csv(os.path.join(DATA_DIR, 'file_access.csv'))
    file_access['access_time'] = pd.to_datetime(file_access['access_time'], errors='coerce')
    file_access = file_access.dropna(subset=['access_time']).copy()

    usb_usage = pd.read_csv(os.path.join(DATA_DIR, 'usb_usage.csv'))
    usb_usage['plug_time'] = pd.to_datetime(usb_usage['plug_time'], errors='coerce')
    usb_usage['unplug_time'] = pd.to_datetime(usb_usage['unplug_time'], errors='coerce')
    usb_usage = usb_usage.dropna(subset=['plug_time']).copy()

    emails = pd.read_csv(os.path.join(DATA_DIR, 'emails.csv'))
    emails['time'] = pd.to_datetime(emails['time'], errors='coerce')
    emails = emails.dropna(subset=['time']).copy()

    # Load user profiles if available
    profiles_path = os.path.join(DATA_DIR, 'user_profiles.csv')
    profiles = pd.read_csv(profiles_path) if os.path.exists(profiles_path) else None

    return logins, file_access, usb_usage, emails, profiles

def extract_features():
    """Extract behavioral features per user."""
    logins, file_access, usb_usage, emails, profiles = load_logs()

    # Get all users
    users = logins['user'].unique()
    features = []

    # Define business hours
    BUSINESS_START = 9
    BUSINESS_END = 18

    for user in users:
        user_logins = logins[logins['user'] == user]
        user_files = file_access[file_access['user'] == user]
        user_usb = usb_usage[usb_usage['user'] == user]
        user_emails = emails[emails['sender'] == f'{user}@company.com']

        # =====================================================================
        # LOGIN FEATURES
        # =====================================================================

        # Mean login/logout hours
        mean_login_hour = user_logins['login'].dt.hour.mean()
        mean_logout_hour = user_logins['logout'].dt.hour.mean()

        # Login consistency (std dev of login time)
        login_std = user_logins['login'].dt.hour.std()

        # Weekend login ratio
        user_logins['day_of_week'] = user_logins['login'].dt.dayofweek
        weekend_logins = (user_logins['day_of_week'] >= 5).sum()
        weekend_ratio = weekend_logins / len(user_logins) if len(user_logins) > 0 else 0

        # After-hours logins (before 6 AM or after 8 PM)
        after_hours = ((user_logins['login'].dt.hour < 6) | (user_logins['login'].dt.hour > 20)).sum()
        after_hours_ratio = after_hours / len(user_logins) if len(user_logins) > 0 else 0

        # Average work session duration
        session_durations = (user_logins['logout'] - user_logins['login']).dt.total_seconds() / 3600
        avg_session_duration = session_durations.mean()

        # =====================================================================
        # FILE ACCESS FEATURES
        # =====================================================================

        # Files per day
        if len(user_files) > 0:
            user_files['date'] = user_files['access_time'].dt.date
            files_per_day = user_files.groupby('date').size().mean()

            # Unique files accessed
            unique_files = user_files['file'].nunique()

            # File access outside login sessions
            out_of_session = 0
            for _, row in user_files.iterrows():
                session = user_logins[
                    (user_logins['login'] <= row['access_time']) &
                    (user_logins['logout'] >= row['access_time'])
                ]
                if session.empty:
                    out_of_session += 1
            out_of_session_ratio = out_of_session / len(user_files) if len(user_files) > 0 else 0

            # After-hours file access
            file_after_hours = ((user_files['access_time'].dt.hour < BUSINESS_START) |
                               (user_files['access_time'].dt.hour > BUSINESS_END)).sum()
            file_after_hours_ratio = file_after_hours / len(user_files) if len(user_files) > 0 else 0

            # Confidential file access
            confidential_access = user_files['file'].str.contains('confidential', case=False, na=False).sum()
            confidential_ratio = confidential_access / len(user_files) if len(user_files) > 0 else 0

            # Copy/download actions (potential exfiltration)
            copy_actions = user_files['access_type'].isin(['copy', 'download']).sum()
            copy_ratio = copy_actions / len(user_files) if len(user_files) > 0 else 0

            # Large file transfers
            if 'file_size_kb' in user_files.columns:
                large_files = (user_files['file_size_kb'] > 10000).sum()
                large_file_ratio = large_files / len(user_files) if len(user_files) > 0 else 0
            else:
                large_file_ratio = 0

            # Burst access (many files in short time - potential mass download)
            if len(user_files) > 10:
                user_files_sorted = user_files.sort_values('access_time')
                burst_count = 0
                for i in range(len(user_files_sorted) - 9):
                    time_window = (user_files_sorted.iloc[i+9]['access_time'] -
                                  user_files_sorted.iloc[i]['access_time']).total_seconds()
                    if time_window < 600:  # 10 files in 10 minutes
                        burst_count += 1
                burst_ratio = burst_count / max(1, len(user_files) - 9)
            else:
                burst_ratio = 0
        else:
            files_per_day = 0
            unique_files = 0
            out_of_session_ratio = 0
            file_after_hours_ratio = 0
            confidential_ratio = 0
            copy_ratio = 0
            large_file_ratio = 0
            burst_ratio = 0
            file_after_hours = 0

        # =====================================================================
        # USB FEATURES
        # =====================================================================

        if len(user_usb) > 0:
            user_usb['date'] = user_usb['plug_time'].dt.date
            usb_per_day = user_usb.groupby('date').size().mean()

            # Average USB session duration (minutes)
            usb_durations = (user_usb['unplug_time'] - user_usb['plug_time']).dt.total_seconds() / 60
            avg_usb_duration = usb_durations.mean()

            # Total data transferred
            if 'data_transferred_mb' in user_usb.columns:
                total_data_mb = user_usb['data_transferred_mb'].sum()
                max_data_mb = user_usb['data_transferred_mb'].max()
            else:
                total_data_mb = 0
                max_data_mb = 0

            # After-hours USB usage
            usb_after_hours = ((user_usb['plug_time'].dt.hour < BUSINESS_START) |
                              (user_usb['plug_time'].dt.hour > BUSINESS_END)).sum()
            usb_after_hours_ratio = usb_after_hours / len(user_usb) if len(user_usb) > 0 else 0

            # Long USB sessions (> 2 hours)
            long_usb = (usb_durations > 120).sum()
            long_usb_ratio = long_usb / len(user_usb) if len(user_usb) > 0 else 0
        else:
            usb_per_day = 0
            avg_usb_duration = 0
            total_data_mb = 0
            max_data_mb = 0
            usb_after_hours_ratio = 0
            long_usb_ratio = 0
            usb_after_hours = 0

        # =====================================================================
        # EMAIL FEATURES
        # =====================================================================

        if len(user_emails) > 0:
            user_emails['date'] = user_emails['time'].dt.date
            emails_per_day = user_emails.groupby('date').size().mean()

            # After-hours emails
            email_after_hours = ((user_emails['time'].dt.hour < BUSINESS_START) |
                                (user_emails['time'].dt.hour > BUSINESS_END)).sum()
            email_after_hours_ratio = email_after_hours / len(user_emails) if len(user_emails) > 0 else 0

            # Emails with attachments
            if 'has_attachment' in user_emails.columns:
                attachment_ratio = user_emails['has_attachment'].sum() / len(user_emails)
            else:
                attachment_ratio = 0

            # External recipients (personal email addresses)
            if 'recipient' in user_emails.columns:
                external = user_emails['recipient'].str.contains('gmail|yahoo|hotmail|outlook',
                                                                 case=False, na=False).sum()
                external_ratio = external / len(user_emails) if len(user_emails) > 0 else 0
            else:
                external_ratio = 0

            # Average word count
            if 'word_count' in user_emails.columns:
                avg_word_count = user_emails['word_count'].mean()
            else:
                avg_word_count = 0
        else:
            emails_per_day = 0
            email_after_hours_ratio = 0
            attachment_ratio = 0
            external_ratio = 0
            avg_word_count = 0
            email_after_hours = 0

        # =====================================================================
        # COMPOSITE RISK INDICATORS
        # =====================================================================

        # Overall after-hours activity ratio
        total_after_hours = after_hours + file_after_hours + usb_after_hours + email_after_hours
        total_events = len(user_logins) + len(user_files) + len(user_usb) + len(user_emails)
        overall_after_hours_ratio = total_after_hours / total_events if total_events > 0 else 0

        # Data movement score
        data_movement = (copy_ratio * 0.3 + large_file_ratio * 0.3 +
                        (min(total_data_mb, 5000) / 5000) * 0.2 + burst_ratio * 0.2)

        features.append({
            'user': user,
            # Login features
            'mean_login_hour': mean_login_hour,
            'mean_logout_hour': mean_logout_hour,
            'login_time_std': login_std if not np.isnan(login_std) else 0,
            'weekend_login_ratio': weekend_ratio,
            'after_hours_login_ratio': after_hours_ratio,
            'avg_session_duration_hours': avg_session_duration,
            # File access features
            'files_per_day': files_per_day,
            'unique_files_accessed': unique_files,
            'out_of_session_access_ratio': out_of_session_ratio,
            'file_after_hours_ratio': file_after_hours_ratio,
            'confidential_file_ratio': confidential_ratio,
            'file_copy_ratio': copy_ratio,
            'large_file_ratio': large_file_ratio,
            'burst_access_ratio': burst_ratio,
            # USB features
            'usb_per_day': usb_per_day,
            'avg_usb_duration_min': avg_usb_duration,
            'total_data_transferred_mb': total_data_mb,
            'max_data_transferred_mb': max_data_mb,
            'usb_after_hours_ratio': usb_after_hours_ratio,
            'long_usb_session_ratio': long_usb_ratio,
            # Email features
            'emails_per_day': emails_per_day,
            'email_after_hours_ratio': email_after_hours_ratio,
            'email_attachment_ratio': attachment_ratio,
            'external_email_ratio': external_ratio,
            'avg_email_word_count': avg_word_count,
            # Composite features
            'overall_after_hours_ratio': overall_after_hours_ratio,
            'data_movement_score': data_movement
        })

    df = pd.DataFrame(features)

    # Merge with user profiles to get risk_profile
    if profiles is not None and 'risk_profile' in profiles.columns:
        df = df.merge(profiles[['user_id', 'risk_profile', 'department', 'role']],
                     left_on='user', right_on='user_id', how='left')
        df['risk_profile'] = df['risk_profile'].fillna('low')
        df['department'] = df['department'].fillna('Unknown')
        df['role'] = df['role'].fillna('Unknown')
        df = df.drop(columns=['user_id'])

    df.to_csv(os.path.join(DATA_DIR, 'features.csv'), index=False)
    print(f'Features extracted for {len(df)} users -> data/features.csv')
    return df

if __name__ == '__main__':
    extract_features()
