#!/bin/bash

# Real-Time Simulation Runner
# Runs the live demo simulation for the Insider Threat Detection Dashboard
# Use this to demonstrate real-time threat detection capabilities

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo ""
echo -e "${BLUE}╔════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║   Live Demo Simulation Runner                         ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════════╝${NC}"
echo ""

# Check if data exists
if [ ! -f "data/merged_features.csv" ] || [ ! -f "data/anomaly_scores.csv" ]; then
    echo -e "${YELLOW}No processed data found. Running full pipeline first...${NC}"
    echo ""
    ./start.sh
    exit $?
fi

# Check if red team data exists
if [ ! -f "data/red_team_users.csv" ]; then
    echo -e "${YELLOW}Red team data not found. Injecting red team behaviors...${NC}"
    python data/simulate_red_team.py
    echo -e "${GREEN}✓ Red team injection complete${NC}"
fi

echo ""
echo -e "${GREEN}╔════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║   Starting Live Demo Dashboard                        ║${NC}"
echo -e "${GREEN}║                                                       ║${NC}"
echo -e "${GREEN}║   Navigate to the 'Live Demo' tab to see:            ║${NC}"
echo -e "${GREEN}║   - Normal baseline behavior                          ║${NC}"
echo -e "${GREEN}║   - Suspicious activity detection                     ║${NC}"
echo -e "${GREEN}║   - Real-time alert generation                        ║${NC}"
echo -e "${GREEN}║   - Investigation workflow                            ║${NC}"
echo -e "${GREEN}║                                                       ║${NC}"
echo -e "${GREEN}║   Press Ctrl+C to stop                                ║${NC}"
echo -e "${GREEN}╚════════════════════════════════════════════════════════╝${NC}"
echo ""

# Launch dashboard with auto-refresh enabled
streamlit run dashboard/combined_dashboard.py --server.headless true
