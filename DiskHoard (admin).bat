@echo off
REM Lanza DiskHoard con permisos de administrador: permite leer carpetas
REM protegidas del sistema que si no aparecen como "sin permiso".
powershell -NoProfile -Command "Start-Process -FilePath '%~dp0DiskHoard.bat' -Verb RunAs"
