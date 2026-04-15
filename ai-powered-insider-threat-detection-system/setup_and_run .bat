@echo off
REM Windows Python 3.8 Auto-Installer for AI-Powered Insider Threat Detection System
REM This script downloads and installs Python 3.8, then runs the project

echo.
echo ╔════════════════════════════════════════════════════════╗
echo    Python 3.8 Auto-Installer
echo    AI-Powered Insider Threat Detection System
echo ╚════════════════════════════════════════════════════════╝
echo.

REM Check if Python is already installed
python --version >nul 2>&1
if %errorlevel% equ 0 (
    echo [✓] Python is already installed
    python --version
    echo.
    goto :run_project
)

echo [!] Python not found. Installing Python 3.8...
echo.

REM Create temp directory
if not exist "temp_installer" mkdir temp_installer
cd temp_installer

REM Download Python 3.8.10 installer (64-bit)
echo [1/3] Downloading Python 3.8.10 installer...
curl -L -o python-3.8.10-amd64.exe https://www.python.org/ftp/python/3.8.10/python-3.8.10-amd64.exe

if %errorlevel% neq 0 (
    echo [!] Download failed. Please install Python manually from:
    echo     https://www.python.org/downloads/release/python-3810/
    echo.
    cd ..
    rmdir /s /q temp_installer
    pause
    exit /b 1
)

echo [✓] Download complete
echo.

REM Install Python silently with PATH option
echo [2/3] Installing Python 3.8.10...
echo       This may take a few minutes...
python-3.8.10-amd64.exe /quiet InstallAllUsers=0 PrependPath=1 Include_test=0

REM Wait for installation to complete
timeout /t 10 /nobreak >nul

echo [✓] Installation complete
echo.

REM Clean up installer
echo [3/3] Cleaning up...
del python-3.8.10-amd64.exe
cd ..
rmdir /s /q temp_installer
echo [✓] Cleanup complete
echo.

REM Refresh environment variables
echo [!] Refreshing environment variables...
for /f "skip=2 tokens=2*" %%a in ('reg query "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v PATH') do (
    set "PATH=%%b"
)

echo.
echo ╔════════════════════════════════════════════════════════╗
echo    Python 3.8 Installation Complete!
echo ╚════════════════════════════════════════════════════════╝
echo.

:run_project
echo.
echo ════════════════════════════════════════════════════════
echo    Starting AI-Powered Insider Threat Detection System
echo ════════════════════════════════════════════════════════
echo.

REM Check if virtual environment exists
if exist "venv\Scripts\activate.bat" (
    echo [✓] Virtual environment found
    call venv\Scripts\activate.bat
) else (
    echo [!] Creating virtual environment...
    python -m venv venv
    call venv\Scripts\activate.bat
    echo [✓] Virtual environment created and activated
    echo [!] Installing dependencies...
    pip install -q -r requirements.txt
)

echo.

REM Step 1: Generate simulated data
echo [1/5] Generating Enhanced Simulated Data...
echo       Creating realistic user profiles, login patterns, file access,
echo       USB usage, and email communications...
python data\simulate_logs.py
echo [✓] Data generation complete
echo.

REM Step 2: Inject red team behaviors
echo [2/5] Injecting Red Team Behaviors...
echo       Adding malicious patterns: after-hours access, mass downloads,
echo       confidential file access, suspicious USB usage...
python data\simulate_red_team.py
echo [✓] Red team injection complete
echo.

REM Step 3: Feature engineering
echo [3/5] Engineering Features...
echo       Extracting behavioral, graph, and NLP features...
python features\feature_engineering.py
python features\nlp_email_features.py
python gnn\gnn_anomaly.py
python features\merge_features.py
echo [✓] Feature engineering complete
echo.

REM Step 4: Train models
echo [4/5] Training Anomaly Detection Models...
echo       Training Isolation Forest, One-Class SVM, and Autoencoder...
python models\train.py
echo [✓] Model training complete
echo.

REM Step 5: Launch dashboard
echo [5/5] Launching Dashboard...
echo.
echo ╔════════════════════════════════════════════════════════╗
echo    Dashboard starting at http://localhost:8501
echo    Press Ctrl+C to stop
echo ╚════════════════════════════════════════════════════════╝
echo.
streamlit run dashboard\combined_dashboard.py
