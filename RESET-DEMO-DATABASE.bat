@echo off
title RuralX Demo Database Reset
cd /d "%~dp0"
if exist ruralx.db del /q ruralx.db
if exist ruralx.db-shm del /q ruralx.db-shm
if exist ruralx.db-wal del /q ruralx.db-wal
if exist sessions.sqlite del /q sessions.sqlite
if exist sessions.sqlite-shm del /q sessions.sqlite-shm
if exist sessions.sqlite-wal del /q sessions.sqlite-wal
echo.
echo RuralX demo database reset successfully.
echo Start the website with: npm start
echo.
pause
