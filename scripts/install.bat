@echo off
title Boson Infinity — Installer v2.1.0
color 0B
echo.
echo  ============================================
echo       BOSON INFINITY — INSTALLER v2.1.0
echo  ============================================
echo.
echo  This will install Boson Infinity to:
echo    %LOCALAPPDATA%\BosonInfinity
echo.
echo  Components:
echo    [1] boson-node.exe   — Full blockchain node
echo    [2] boson-cli.exe    — Command-line interface
echo    [3] boson-miner.exe  — CPU miner
echo    [4] boson-wallet.exe — Desktop wallet
echo    [5] boson-oracle.exe — Energy oracle
echo.
pause

set "INSTALL_DIR=%LOCALAPPDATA%\BosonInfinity"
set "DATA_DIR=%LOCALAPPDATA%\BosonInfinity\data"
set "BIN_DIR=%INSTALL_DIR%\bin"

echo.
echo [1/5] Creating directories...
if not exist "%INSTALL_DIR%" mkdir "%INSTALL_DIR%"
if not exist "%BIN_DIR%" mkdir "%BIN_DIR%"
if not exist "%DATA_DIR%" mkdir "%DATA_DIR%"

echo [2/5] Copying binaries...
copy /Y boson-node.exe "%BIN_DIR%\" >nul
copy /Y boson-cli.exe "%BIN_DIR%\" >nul
copy /Y boson-miner.exe "%BIN_DIR%\" >nul
copy /Y boson-wallet.exe "%BIN_DIR%\" >nul
copy /Y boson-oracle.exe "%BIN_DIR%\" >nul

echo [3/5] Creating default config...
if not exist "%DATA_DIR%\boson.env" (
    copy /Y boson.env.example "%DATA_DIR%\boson.env" >nul
    echo   Created boson.env in %DATA_DIR%
    echo   IMPORTANT: Edit this file before running the node!
) else (
    echo   boson.env already exists, skipping
)

echo [4/5] Creating shortcuts...

REM Create start-node.bat
(
echo @echo off
echo title Boson Infinity Node
echo cd /d "%DATA_DIR%"
echo "%BIN_DIR%\boson-node.exe"
echo pause
) > "%INSTALL_DIR%\Start Node.bat"

REM Create start-wallet.bat
(
echo @echo off
echo title Boson Infinity Wallet
echo cd /d "%DATA_DIR%"
echo "%BIN_DIR%\boson-wallet.exe"
echo pause
) > "%INSTALL_DIR%\Start Wallet.bat"

REM Create start-miner.bat
(
echo @echo off
echo title Boson Infinity Miner
echo cd /d "%DATA_DIR%"
echo echo Set BOSON_NODE_URL, BOSON_API_KEY, BOSON_WALLET before running!
echo echo.
echo if "%%BOSON_WALLET%%"=="" (
echo     echo ERROR: BOSON_WALLET not set
echo     pause
echo     exit /b 1
echo ^)
echo "%BIN_DIR%\boson-miner.exe"
echo pause
) > "%INSTALL_DIR%\Start Miner.bat"

echo [5/5] Adding to PATH...
REM Check if already in PATH
echo %PATH% | findstr /I /C:"%BIN_DIR%" >nul 2>&1
if errorlevel 1 (
    setx PATH "%PATH%;%BIN_DIR%" >nul 2>&1
    if errorlevel 1 (
        echo   WARNING: Could not add to PATH automatically.
        echo   Add this manually: %BIN_DIR%
    ) else (
        echo   Added %BIN_DIR% to PATH
    )
) else (
    echo   Already in PATH
)

echo.
echo  ============================================
echo       INSTALLATION COMPLETE!
echo  ============================================
echo.
echo  Install dir:  %INSTALL_DIR%
echo  Data dir:     %DATA_DIR%
echo  Config:       %DATA_DIR%\boson.env
echo.
echo  NEXT STEPS:
echo    1. Edit %DATA_DIR%\boson.env
echo       Set BOSON_API_KEY and BOSON_TREASURY_ADDR
echo.
echo    2. Run "Start Node.bat" to launch the node
echo       Open http://localhost:8080/explorer for block explorer
echo.
echo    3. Run "Start Wallet.bat" for the desktop wallet
echo       Open http://localhost:8090 for wallet GUI
echo.
echo    4. Run "boson-cli status" from any terminal to check node
echo.
pause
