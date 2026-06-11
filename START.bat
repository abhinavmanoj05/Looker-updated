@echo off
echo =============================================================
echo  Looker Threat Intelligence Platform — Police Cyber Cell
echo =============================================================
echo.
echo [1/3] Checking Docker containers...
docker-compose up -d
echo.
echo [2/3] Installing Python dependencies...
pip install -r backend/requirements.txt -q
echo.
echo [3/3] Starting Looker Intelligence Server...
echo.
echo  Open your browser at: http://localhost:8000
echo.
python backend/app.py

