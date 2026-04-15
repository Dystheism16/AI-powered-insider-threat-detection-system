import subprocess
import sys
import os

# Colors for terminal output
GREEN = '\033[92m'
YELLOW = '\033[93m'
BLUE = '\033[94m'
NC = '\033[0m' # No Color

def run_script(script_path, description):
    print(f"{YELLOW}[RUNNING]{NC} {description}...")
    try:
        # Use sys.executable to ensure we use the current Python environment
        subprocess.check_call([sys.executable, script_path])
        print(f"{GREEN}✓ Completed: {description}{NC}\n")
    except subprocess.CalledProcessError as e:
        print(f"\033[91m❌ Error occurred while running {script_path}: {e}\033[0m")
        sys.exit(1)

def main():
    print(f"{BLUE}╔════════════════════════════════════════════════════════╗{NC}")
    print(f"{BLUE}║   AI-Powered Insider Threat Detection System (Windows)  ║{NC}")
    print(f"{BLUE}╚════════════════════════════════════════════════════════╝{NC}\n")

    pipeline = [
        ("data/simulate_logs.py", "Generating Simulated Logs"),
        ("data/simulate_red_team.py", "Injecting Red Team Behaviors"),
        ("features/feature_engineering.py", "Extracting Behavioral Features"),
        ("features/nlp_email_features.py", "Extracting NLP Email Features"),
        ("gnn/gnn_anomaly.py", "Computing Graph Features"),
        ("features/merge_features.py", "Merging All Feature Sets"),
        ("models/train.py", "Training Anomaly Detection Models"),
    ]

    for script, desc in pipeline:
        run_script(script, desc)

    print(f"{YELLOW}[LAUNCHING]{NC} Starting Dashboard...")
    print(f"{GREEN}Dashboard starting at http://localhost:8501{NC}")
    
    # Launch Streamlit using the python module approach for Windows compatibility
    try:
        subprocess.run([sys.executable, "-m", "streamlit", "run", "dashboard/combined_dashboard.py"])
    except KeyboardInterrupt:
        print("\nDashboard stopped by user.")

if __name__ == "__main__":
    main()
