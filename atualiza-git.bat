@rem atualiza-git.bat
@echo off
rem goto fim
%~d0
cd "%~p0"
rem git config --local user.name "Eduardo"
rem git config --local user.email "edu.a1978@gmail.com"
git.exe fetch
git.exe pull
git.exe add .
git.exe commit -m "novo backup"
git.exe push
pause
goto fim
:fim
