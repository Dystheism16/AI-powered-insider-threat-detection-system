"""
Feature Merger

Merges all feature sets into a single file for model training:
- Behavioral features (from feature_engineering.py)
- Graph features (from gnn/gnn_anomaly.py)
- NLP features (from nlp_email_features.py)
"""

import pandas as pd
import os

DATA_DIR = 'data'

def main():
    print("=" * 50)
    print("Feature Merger")
    print("=" * 50)

    # Load behavioral features
    features_path = os.path.join(DATA_DIR, 'features.csv')
    if os.path.exists(features_path):
        df_classic = pd.read_csv(features_path)
        print(f"Loaded behavioral features: {len(df_classic)} users, {len(df_classic.columns)} features")
    else:
        print("Running feature engineering...")
        import sys
        sys.path.append('.')
        from features.feature_engineering import extract_features
        df_classic = extract_features()

    # Load graph features
    graph_path = os.path.join(DATA_DIR, 'graph_features.csv')
    if os.path.exists(graph_path):
        df_graph = pd.read_csv(graph_path)
        print(f"Loaded graph features: {len(df_graph)} users, {len(df_graph.columns)} features")
    else:
        print("Running graph feature extraction...")
        import sys
        sys.path.append('.')
        from gnn.gnn_anomaly import compute_graph_features
        df_graph = compute_graph_features()

    # Load NLP features
    nlp_path = os.path.join(DATA_DIR, 'nlp_email_features.csv')
    if os.path.exists(nlp_path):
        df_nlp = pd.read_csv(nlp_path)
        print(f"Loaded NLP features: {len(df_nlp)} records")
    else:
        print("Running NLP feature extraction...")
        import sys
        sys.path.append('.')
        from features.nlp_email_features import extract_features
        extract_features()
        df_nlp = pd.read_csv(nlp_path)

    # Aggregate NLP features per user
    df_nlp['user'] = df_nlp['sender'].str.replace('@company.com', '', regex=False)
    df_nlp_agg = df_nlp.groupby('user').agg({
        'keyword_flag': 'mean',
        'subject_len': 'mean',
        'sentiment': 'mean'
    }).reset_index()
    df_nlp_agg.columns = ['user', 'keyword_flag', 'subject_len', 'sentiment']
    print(f"Aggregated NLP features: {len(df_nlp_agg)} users")

    # Merge all features
    print("\nMerging features...")
    df = df_classic.merge(df_graph, on='user', how='left')
    df = df.merge(df_nlp_agg, on='user', how='left')

    # Load red team labels
    red_team_path = os.path.join(DATA_DIR, 'red_team_users.csv')
    if os.path.exists(red_team_path):
        red_team_df = pd.read_csv(red_team_path)
        if 'user' in red_team_df.columns:
            red_team = red_team_df['user'].tolist()
        elif 'user_id' in red_team_df.columns:
            red_team = red_team_df['user_id'].tolist()
        else:
            red_team = []
        df['is_red_team'] = df['user'].isin(red_team).astype(int)
        print(f"Red team labels loaded: {sum(df['is_red_team'])} malicious users")
    else:
        df['is_red_team'] = 0
        print("No red team labels found (all users marked as benign)")

    # Fill missing values
    df = df.fillna(0)

    # Save merged features
    output_path = os.path.join(DATA_DIR, 'merged_features.csv')
    df.to_csv(output_path, index=False)
    print(f"\nMerged features saved to {output_path}")
    print(f"Total: {len(df)} users, {len(df.columns)} features")

    # Show feature columns
    print("\nFeature columns:")
    for col in df.columns:
        if col != 'user':
            print(f"  - {col}")

    return df

if __name__ == '__main__':
    main()
