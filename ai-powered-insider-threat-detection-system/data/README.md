# Data Directory

## CMU Insider Threat Dataset

To use the Carnegie Mellon University Insider Threat Dataset:

1. Download from: https://www.cert.org/insider-threat/tools-and-data/
2. Extract to `data/cmu_dataset/`

Expected structure:
```
data/cmu_dataset/
    - logins.csv
    - http.csv
    - emails.csv
    - file.csv
    - device.csv
    - red_team.csv (optional - known malicious users)
```

3. Run the loader:
```bash
python data/load_cmu_data.py
```

4. Continue with standard pipeline:
```bash
python features/merge_features.py
python models/train.py
streamlit run dashboard/combined_dashboard.py
```

## Simulated Data

If CMU dataset is not available, the system generates simulated logs:

```bash
python data/simulate_logs.py
python data/simulate_red_team.py
```

## Output Files

After running the pipeline, these files are generated:
- `logins.csv` - User login/logout records
- `file_access.csv` - File access events
- `usb_usage.csv` - USB device usage
- `emails.csv` - Email communications
- `features.csv` - Behavioral features
- `graph_features.csv` - Graph-based features
- `nlp_email_features.csv` - NLP features from emails
- `merged_features.csv` - Combined feature set
- `anomaly_scores.csv` - Model anomaly scores
- `red_team_users.csv` - Known malicious users (for evaluation)
