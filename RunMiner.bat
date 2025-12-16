@echo off
title Boson Infinity GPU Miner

echo ============================================
echo      Boson Infinity - GPU Miner Starter
echo ============================================

REM --------------------------------------------
REM CONFIG required for miner to connect
REM --------------------------------------------

REM Node (Twój publiczny testnet/mainnet)
set NODE_URL=http://94.130.151.250

REM Miner ID (API key lub label)
set MINER_KEY=ef5251f535ed7143b31398c1128d3b6a6ecbb011eb45f10205251f7192be1669

REM Wallet address użytkownika
set WALLET=db92fe3a2720cc19256d9a1bab691346ef823e3a

REM Oracle address
set BFI_ENERGY_ORACLE_URL=http://94.130.151.250:8090

REM Secret do walidacji raportów
set BFI_ORACLE_SECRET=e2c4dbe468705a18f20c83f94b5a174ccc5707ac314c19c2bebff1563c1d6b04


echo [STARTING MINER]
miner_gpu.exe %NODE_URL% %MINER_KEY% %WALLET%
pause
