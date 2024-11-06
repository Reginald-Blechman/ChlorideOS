@echo off
powershell -ExecutionPolicy Bypass -Command "Checkpoint-Computer -Description 'Exm Premium Restore Point' -RestorePointType 'MODIFY_SETTINGS'" 
