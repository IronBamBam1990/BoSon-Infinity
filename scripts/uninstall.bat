@echo off
title Boson Infinity — Uninstaller
color 0C
echo.
echo  ============================================
echo       BOSON INFINITY — UNINSTALLER
echo  ============================================
echo.
echo  This will remove Boson Infinity binaries from:
echo    %LOCALAPPDATA%\BosonInfinity\bin
echo.
echo  Your data (chain, wallet, config) in:
echo    %LOCALAPPDATA%\BosonInfinity\data
echo  will NOT be deleted.
echo.
set /p CONFIRM="Are you sure? (Y/N): "
if /I not "%CONFIRM%"=="Y" (
    echo Cancelled.
    pause
    exit /b 0
)

set "INSTALL_DIR=%LOCALAPPDATA%\BosonInfinity"
set "BIN_DIR=%INSTALL_DIR%\bin"

echo.
echo Removing binaries...
if exist "%BIN_DIR%\boson-node.exe" del /Q "%BIN_DIR%\boson-node.exe"
if exist "%BIN_DIR%\boson-cli.exe" del /Q "%BIN_DIR%\boson-cli.exe"
if exist "%BIN_DIR%\boson-miner.exe" del /Q "%BIN_DIR%\boson-miner.exe"
if exist "%BIN_DIR%\boson-wallet.exe" del /Q "%BIN_DIR%\boson-wallet.exe"
if exist "%BIN_DIR%\boson-oracle.exe" del /Q "%BIN_DIR%\boson-oracle.exe"

echo Removing shortcuts...
if exist "%INSTALL_DIR%\Start Node.bat" del /Q "%INSTALL_DIR%\Start Node.bat"
if exist "%INSTALL_DIR%\Start Wallet.bat" del /Q "%INSTALL_DIR%\Start Wallet.bat"
if exist "%INSTALL_DIR%\Start Miner.bat" del /Q "%INSTALL_DIR%\Start Miner.bat"

echo.
echo  Binaries removed.
echo  Data directory preserved: %INSTALL_DIR%\data
echo  To remove all data: rmdir /S /Q "%INSTALL_DIR%"
echo.
pause
