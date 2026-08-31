@echo off
title DiskHoard
cd /d "%~dp0"

set "PYEXE="
where py >nul 2>nul && set "PYEXE=py -3"
if not defined PYEXE (
  where python >nul 2>nul && set "PYEXE=python"
)
if not defined PYEXE if exist "C:\Python313\python.exe" set "PYEXE=C:\Python313\python.exe"
if not defined PYEXE if exist "%LOCALAPPDATA%\Programs\Python\Python313\python.exe" set "PYEXE=%LOCALAPPDATA%\Programs\Python\Python313\python.exe"

if not defined PYEXE (
  echo.
  echo   No se ha encontrado Python en este equipo.
  echo   Instalalo desde https://www.python.org/downloads/ y vuelve a ejecutar esto.
  echo.
  pause
  exit /b 1
)

echo.
echo   Arrancando DiskHoard... se abrira solo en el navegador.
echo   Deja esta ventana abierta mientras lo uses.
echo.
%PYEXE% -u -m diskhoard %*
echo.
pause
