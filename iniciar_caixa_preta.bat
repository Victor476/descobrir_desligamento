@echo off
chcp 65001 >nul
cd /d "%~dp0"

echo ========================================================================
echo   CAIXA-PRETA - MONITORAMENTO CONTINUO ATE O DESLIGAMENTO
echo ========================================================================
echo.
echo Deixe esta janela aberta enquanto usa ou joga normalmente.
echo Cada leitura e gravada imediatamente no disco (fsync).
echo Quando o PC desligar e voce ligar novamente, execute "executar_diagnostico.bat".
echo.

python main.py --monitor --intervalo 2
echo.
pause
