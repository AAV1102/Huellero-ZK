@echo off
REM Sincroniza reloj UA-300 con CSV local (AVERABYTE_LABS)
cd /d "%~dp0"
call entorno_virtual_genesis\Scripts\activate
python sync_only.py