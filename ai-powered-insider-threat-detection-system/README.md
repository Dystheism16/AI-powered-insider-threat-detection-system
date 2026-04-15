# AI-Powered Insider Threat Detection System

> **Major Project Submission** - Detects insider threats using machine learning by analyzing user behavior, file access patterns, USB usage, and email communications.

![Dashboard Preview](https://img.shields.io/badge/Status-Complete-success)
![Python](https://img.shields.io/badge/Python-3.8+-blue)
![ML Models](https://img.shields.io/badge/Models-Isolation%20Forest%7COne--Class%20SVM%7CAutoencoder-orange)

---

## 📋 Overview

This system detects insider threats using unsupervised machine learning algorithms. It analyzes:
- **Login patterns** - Work hours, weekend access, consistency
- **File access** - Unusual files, after-hours access, mass downloads
- **USB usage** - Data transfer volumes, unusual timing
- **Email communications** - Suspicious subjects, external recipients

The system generates **enhanced simulated data** that mimics real organizational activity with realistic user profiles, departments, and job roles.

---

## 🚀 Quick Start

### Single Command Startup
```bash
./start.sh
```

This script will:
1. ✅ Create/activate virtual environment
2. ✅ Generate enhanced simulated data (25 users, 60 days)
3. ✅ Inject red team behaviors (malicious insiders)
4. ✅ Engineer 40+ features (behavioral, graph, NLP)
5. ✅ Train 3 anomaly detection models
6. ✅ Launch interactive dashboard

**Dashboard opens at:** `http://localhost:8501`

---

## 📊 Dashboard Features

| Tab | Description |
|-----|-------------|
| 🚨 **Real-Time Alerts** | Users exceeding anomaly threshold with risk cards |
| 📊 **Anomaly Table** | Sortable, filterable table with Red Team indicators |
| 📈 **Time-Series Analysis** | Login trends, after-hours activity, score distributions |
| 👤 **User Detail** | Complete behavioral profile for any user |
| 🕸️ **At-Risk Graph** | Interactive network visualization of suspicious activity |
| ❓ **How It Works** | System documentation and methodology |

---

## 🏗️ System Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    DATA LAYER                               │
│  ┌─────────────┐ ┌──────────────┐ ┌──────────┐ ┌────────┐  │
│  │  Logins     │ │ File Access  │ │   USB    │ │ Emails │  │
│  │  (2.5K+)    │ │  (50K+)      │ │ (500+)   │ │(2K+)   │  │
│  └─────────────┘ └──────────────┘ └──────────┘ └────────┘  │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│                 FEATURE ENGINEERING                         │
│  • Behavioral Features (login patterns, session duration)   │
│  • File Access Features (confidential access, burst reads)  │
│  • USB Features (data transfer, duration)                   │
│  • Email Features (sentiment, external recipients)          │
│  • Graph Features (centrality, PageRank)                    │
│  • NLP Features (keyword flags, subject analysis)           │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│              ANOMALY DETECTION MODELS                       │
│  ┌─────────────────┐ ┌─────────────────┐ ┌──────────────┐  │
│  │ Isolation Forest│ │  One-Class SVM  │ │  Autoencoder │  │
│  │  (Tree-based)   │ │  (Kernel-based) │ │  (Neural Net)│  │
│  └─────────────────┘ └─────────────────┘ └──────────────┘  │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│                  INTERACTIVE DASHBOARD                      │
│  Streamlit-based UI with real-time alerts & visualization   │
└─────────────────────────────────────────────────────────────┘
```

---

## 📁 Project Structure

```
ai-powered-insider-threat-detection-system/
├── data/
│   ├── simulate_logs.py         # Enhanced data generator
│   ├── simulate_red_team.py     # Malicious behavior injector
│   └── load_cmu_data.py         # CMU dataset loader (optional)
├── features/
│   ├── feature_engineering.py   # Behavioral features
│   ├── nlp_email_features.py    # Email analysis with VADER
│   └── merge_features.py        # Feature consolidation
├── gnn/
│   └── gnn_anomaly.py           # Graph feature extraction
├── models/
│   └── train.py                 # Model training pipeline
├── dashboard/
│   └── combined_dashboard.py    # Main dashboard (6 tabs)
├── explainability/
│   └── explain.py               # SHAP & LIME explanations
├── requirements.txt
├── start.sh                     # Unified startup script
└── README.md
```

---

## 🔬 Technical Details

### Data Generation
- **25 users** across 8 departments (Engineering, Finance, HR, IT, etc.)
- **60 days** of activity (~3,000 login sessions)
- **Realistic work patterns** based on job roles
- **5 red team members** with injected malicious behaviors

### Feature Set (40+ features)
| Category | Features |
|----------|----------|
| **Login** | Mean login hour, session duration, weekend ratio, after-hours ratio |
| **File Access** | Files/day, out-of-session access, confidential file ratio, burst access |
| **USB** | Sessions/day, data transferred, after-hours usage, long sessions |
| **Email** | Emails/day, external recipients, attachment ratio, sentiment |
| **Graph** | Degree centrality, betweenness, PageRank, clustering coefficient |
| **NLP** | Keyword flags, subject length, sentiment score |

### Machine Learning Models

| Model | Type | Purpose |
|-------|------|---------|
| **Isolation Forest** | Ensemble (Trees) | Primary anomaly scorer |
| **One-Class SVM** | Kernel-based | Boundary-based detection |
| **Autoencoder** | Neural Network | Reconstruction error |

### Detection Threshold
- **Alert Level:** 95th percentile of anomaly scores
- **High Risk:** Score > 1.0 OR red team label
- **Critical:** Multiple model agreement

---

## 🛠️ Installation

### Prerequisites
- Python 3.8+
- pip

### Setup
```bash
# Clone or download the project
cd ai-powered-insider-threat-detection-system

# Install dependencies
pip install -r requirements.txt

# Run the project
./start.sh
```

### Requirements
```
numpy, pandas, scikit-learn     # ML & data processing
matplotlib, seaborn, plotly     # Visualization
streamlit                       # Dashboard
shap, lime                      # Explainability
networkx, pyvis                 # Graph analysis
vaderSentiment                  # NLP sentiment
```

---

## 📊 Dataset Information

### Simulated Data (Default)
The system generates realistic synthetic data:
- User profiles with departments and job roles
- Work hour patterns (varies by role)
- Realistic file system structure
- Corporate email patterns
- USB device usage

**File sizes after generation:**
- `logins.csv` ~500 KB
- `file_access.csv` ~5 MB
- `usb_usage.csv` ~50 KB
- `emails.csv` ~300 KB

### CMU Dataset (Optional)
For real-world evaluation, integrate CMU's Insider Threat Dataset:
1. Download from: https://www.cert.org/insider-threat/tools-and-data/
2. Place in `data/cmu_dataset/`
3. Run: `python data/load_cmu_data.py`

---

## 🎯 Red Team Behaviors

The system injects these realistic malicious patterns:

| Behavior | Description | Detection Signal |
|----------|-------------|------------------|
| **After-Hours Access** | 2-5 AM file access | Unusual login times |
| **Mass Downloads** | 30-50 files in minutes | Burst access pattern |
| **Confidential Access** | HR/Finance accessing secrets | Role mismatch |
| **Large USB Transfers** | 500MB-5GB data transfers | Volume anomaly |
| **External Emails** | Sending to personal accounts | Recipient anomaly |

---

## 📈 Dashboard Screenshots

### Alerts Tab
- Real-time risk cards for flagged users
- Summary statistics (total users, alert rate, confirmed threats)

### Time-Series Tab
- Daily login trends
- Anomaly score histograms with threshold
- After-hours activity timeline

### Graph Tab
- Interactive NetworkX/PyVis visualization
- Color-coded risk levels (red=confirmed, orange=high, yellow=elevated)

---

## 🔍 Explainability

The system includes SHAP and LIME explanations:
```bash
python explainability/explain.py
```

This shows why specific users were flagged, listing feature contributions.

---

## 📝 Manual Pipeline Steps

If you prefer running steps individually:

```bash
# 1. Generate data
python data/simulate_logs.py
python data/simulate_red_team.py

# 2. Extract features
python features/feature_engineering.py
python features/nlp_email_features.py
python gnn/gnn_anomaly.py
python features/merge_features.py

# 3. Train models
python models/train.py

# 4. Launch dashboard
streamlit run dashboard/combined_dashboard.py
```

---

## 🎓 Academic References

1. Moore, A. P. (2019). *Insider Threat Detection and Mitigation*. CERT Division, Carnegie Mellon University.
2. Liu, F. T., Ting, K. M., & Zhou, Z. H. (2008). Isolation Forest. ICDM.
3. Schölkopf, B., et al. (2001). Estimating the Support of a High-Dimensional Distribution. Neural Computation.
4. Lundberg, S. M., & Lee, S. I. (2017). SHAP: A Unified Approach to Interpreting Model Predictions. NIPS.

---

## 🤝 Contributing

This is a major project submission. Key areas for extension:
- Real-time stream processing (Kafka/Spark)
- Graph Neural Networks for entity analysis
- Deep learning autoencoders
- Integration with SIEM systems

---

## 📄 License

Educational/Academic use. For demonstration purposes.

---

## 👨‍💻 Author

Major Project Submission - Insider Threat Detection using ML

**Built with:** Python, Scikit-learn, Streamlit, NetworkX, Plotly
