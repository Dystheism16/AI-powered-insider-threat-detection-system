import pandas as pd
import os
import re

DATA_DIR = 'data'
SUSPICIOUS_KEYWORDS = ['confidential', 'urgent', 'password', 'secret', 'invoice', 'transfer', 'wire', 'classified']

try:
    from vaderSentiment.vaderSentiment import SentimentIntensityAnalyzer
    analyzer = SentimentIntensityAnalyzer()
    USE_VADER = True
except ImportError:
    USE_VADER = False
    print("Warning: vaderSentiment not installed. Install with: pip install vaderSentiment")

def get_sentiment(text):
    """Get sentiment score using VADER or fallback."""
    if USE_VADER and text:
        scores = analyzer.polarity_scores(str(text))
        # Compound score ranges from -1 (negative) to 1 (positive)
        return scores['compound']
    return 0

def extract_features():
    emails = pd.read_csv(os.path.join(DATA_DIR, 'emails.csv'), parse_dates=['time'])
    features = []
    for _, row in emails.iterrows():
        subject = str(row['subject']).lower() if pd.notna(row['subject']) else ''
        keyword_flag = int(any(kw in subject for kw in SUSPICIOUS_KEYWORDS))
        subject_len = len(subject)
        sentiment = get_sentiment(row.get('subject', ''))
        features.append({
            'sender': row['sender'],
            'recipient': row['recipient'],
            'time': row['time'],
            'keyword_flag': keyword_flag,
            'subject_len': subject_len,
            'sentiment': sentiment
        })
    pd.DataFrame(features).to_csv(os.path.join(DATA_DIR, 'nlp_email_features.csv'), index=False)
    print(f'NLP email features saved to data/nlp_email_features.csv (VADER: {USE_VADER})')

if __name__ == '__main__':
    extract_features() 