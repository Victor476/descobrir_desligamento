@echo off
chcp 65001 >nul
cd /d "%~dp0"

echo ========================================================================
echo   DIAGNOSTICO DE DESLIGAMENTO ALEATORIO DO PC
echo ========================================================================
echo.
echo Dica: Para ler todos os sensores termicos e arquivos de Minidump,
echo clique com o botao direito neste arquivo e escolha "Executar como administrador".
echo.

python main.py --dias 30 --abrir
echo.
pause
