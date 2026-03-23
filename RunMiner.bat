@echo off
title Boson Infinity GPU Miner

echo ============================================
echo      Boson Infinity - GPU Miner Starter
echo ============================================
echo.

REM =========================================================================
REM  IMPORTANT: Set these environment variables BEFORE running this script!
REM  Do NOT hardcode secrets here — use system environment variables.
REM
REM  Required:
REM    BOSON_NODE_URL     = URL of your Boson node (e.g. http://1.2.3.4:8080)
REM    BOSON_API_KEY      = API key matching node config
REM    BOSON_WALLET       = Your 40-hex wallet address
REM
REM  Optional:
REM    BFI_ENERGY_ORACLE_URL = Oracle URL (e.g. http://1.2.3.4:8090)
REM    BFI_ORACLE_SECRET     = HMAC secret for oracle reports
REM    BFI_POWER_WATTS       = Override GPU power estimate (watts)
REM    BFI_MINER_LABEL       = Miner name label
REM    BFI_TRIES             = Tries per round (default: 2000000)
REM    BFI_READS             = Reads per try (default: 2048)
REM =========================================================================

REM ---- Validation ----
if "%BOSON_NODE_URL%"=="" (
    echo [ERROR] BOSON_NODE_URL is not set!
    echo   Set it: set BOSON_NODE_URL=http://your-node-ip:8080
    echo.
    pause
    exit /b 1
)

if "%BOSON_API_KEY%"=="" (
    echo [ERROR] BOSON_API_KEY is not set!
    echo   Set it: set BOSON_API_KEY=your-api-key
    echo.
    pause
    exit /b 1
)

if "%BOSON_WALLET%"=="" (
    echo [ERROR] BOSON_WALLET is not set!
    echo   Set it: set BOSON_WALLET=your-40-hex-wallet-address
    echo.
    pause
    exit /b 1
)

echo [MINER] Node:   %BOSON_NODE_URL%
echo [MINER] Wallet: %BOSON_WALLET%
echo [MINER] Starting GPU miner...
echo.

miner_gpu.exe %BOSON_NODE_URL% %BOSON_API_KEY% %BOSON_WALLET%

pause
