@echo off

 setlocal ENABLEDELAYEDEXPANSION
 set input=%1
 rem echo %input%
 set l=3
 set c=0
 for /f "delims=" %%1 in ('NTHASH-win64.exe /stringtobyte /input:%input%') do (
   rem set /a c+=1 && if "!c!" equ "%l%" echo %%1%
   set /a c+=1 && if "!c!" equ "%l%" set ret=%%1%
 )
rem echo %ret% 
set l=2
set c=0
echo RC2
 for /f "delims=" %%1 in ('NTHASH-win64.exe /getcipher /mode:RC2 /input:%ret%') do (
   set /a c+=1 && if "!c!" equ "%l%" echo %%1%
 )
set l=2
set c=0
echo RC4
 for /f "delims=" %%1 in ('NTHASH-win64.exe /getcipher /mode:RC4 /input:%ret%') do (
   set /a c+=1 && if "!c!" equ "%l%" echo %%1%
 )
set l=2
set c=0
echo RC5
 for /f "delims=" %%1 in ('NTHASH-win64.exe /getcipher /mode:RC5 /input:%ret%') do (
   set /a c+=1 && if "!c!" equ "%l%" echo %%1%
 )
 
