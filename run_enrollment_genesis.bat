
@echo off
REM === Instalador y lanzador de ZK Enrollment GUI ===
REM Crea entorno virtual, instala requisitos y arranca la GUI

set "VENV_DIR=venv"

if not exist %VENV_DIR% (
    echo Creando entorno virtual...
    python -m venv %VENV_DIR%
)

call %VENV_DIR%\Scripts\activate

echo Instalando dependencias...
pip install --upgrade pip >nul
pip install -r requirements.txt

echo Lanzando la interfaz...
python zk_enrollment_gui.py
