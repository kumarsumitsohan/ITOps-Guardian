# Optional helper: creates the virtual environment, installs packages and starts the app.
# Usage (PowerShell, inside the ITOps-Guardian folder):  .\run.ps1
if (-not (Test-Path .\venv)) { python -m venv venv }
.\venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m streamlit run app.py
