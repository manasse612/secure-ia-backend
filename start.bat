@echo off
chcp 65001 >nul
echo.
echo ╔══════════════════════════════════════════════════════════════╗
echo ║           Secure IA - Serveur Auto-Redémarrage                 ║
echo ║                                                              ║
echo ║  Ce serveur redémarre automatiquement en cas d'erreur        ║
echo ║  Peu importe le crash, il revient toujours !                 ║
echo ╚══════════════════════════════════════════════════════════════╝
echo.

set PORT=8003
set HOST=0.0.0.0
set PYTHONIOENCODING=utf-8

:loop
echo [%date% %time%] 🚀 Démarrage du serveur sur port %PORT%...
cd /d "%~dp0"
call .\venv\Scripts\activate

:: Démarrer uvicorn avec reload
python -m uvicorn main:app --host %HOST% --port %PORT% --reload --reload-delay 1 --log-level info

if %errorlevel% neq 0 (
    echo.
    echo ⚠️  Le serveur s'est arrêté avec code %errorlevel%
    echo ⏳ Redémarrage dans 3 secondes...
    echo.
    timeout /t 3 /nobreak >nul
    goto loop
)

echo ✅ Arrêt normal
timeout /t 5
