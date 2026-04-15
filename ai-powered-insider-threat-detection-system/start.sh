#!/bin/bash

# AI-Powered Insider Threat Detection System - Startup Script
# Complete pipeline: Data Generation -> Feature Engineering -> Model Training -> Dashboard

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Activate virtual environment if it exists
if [ -d "venv" ]; then
    source venv/bin/activate
    echo -e "${GREEN}✓ Virtual environment activated${NC}"
else
    echo -e "${YELLOW}Warning: No venv found. Creating one...${NC}"
    python -m venv venv
    source venv/bin/activate
    echo -e "${GREEN}✓ Virtual environment created and activated${NC}"
    echo -e "${YELLOW}Installing dependencies...${NC}"
    pip install -q -r requirements.txt
fi

echo ""
echo -e "${BLUE}╔════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║   AI-Powered Insider Threat Detection System          ║${NC}"
echo -e "${BLUE}║   Major Project Submission                            ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════════╝${NC}"
echo ""

# Step 1: Generate simulated data
echo -e "${YELLOW}[1/5] Generating Enhanced Simulated Data...${NC}"
echo "      Creating realistic user profiles, login patterns, file access,"
echo "      USB usage, and email communications..."
python data/simulate_logs.py
echo -e "${GREEN}      ✓ Data generation complete${NC}"
echo ""

# Step 2: Inject red team behaviors
echo -e "${YELLOW}[2/5] Injecting Red Team Behaviors...${NC}"
echo "      Adding malicious patterns: after-hours access, mass downloads,"
echo "      confidential file access, suspicious USB usage..."
python data/simulate_red_team.py
echo -e "${GREEN}      ✓ Red team injection complete${NC}"
echo ""

# Step 3: Feature engineering
echo -e "${YELLOW}[3/5] Engineering Features...${NC}"
echo "      Extracting behavioral, graph, and NLP features..."
python features/feature_engineering.py
python features/nlp_email_features.py
python gnn/gnn_anomaly.py
python features/merge_features.py
echo -e "${GREEN}      ✓ Feature engineering complete${NC}"
echo ""

# Step 4: Train models
echo -e "${YELLOW}[4/5] Training Anomaly Detection Models...${NC}"
echo "      Training Isolation Forest, One-Class SVM, and Autoencoder..."
python models/train.py
echo -e "${GREEN}      ✓ Model training complete${NC}"
echo ""

# Step 5: Launch dashboard
echo -e "${YELLOW}[5/5] Launching Dashboard...${NC}"
echo ""
echo -e "${GREEN}╔════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║   Dashboard starting at http://localhost:8501         ║${NC}"
echo -e "${GREEN}║   Press Ctrl+C to stop                                ║${NC}"
echo -e "${GREEN}╚════════════════════════════════════════════════════════╝${NC}"
echo ""
streamlit run dashboard/combined_dashboard.py
