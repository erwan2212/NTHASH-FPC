@echo off
rem the below script will 
rem go thru each line in passwords.lst
rem call nthash-win64 /getntlmhash /input:line
rem compare the output of nthash with provided parameter on the command line
rem passwords.lst contains 25 most used passwords from 2011 to 2019 according to SplashData
rem cheap bruteforce ... very slow ... ok for a few passwords ... mode "i am feeling lucky"
setlocal ENABLEDELAYEDEXPANSION
set input=%1
rem for /F "usebackq tokens=*" %%A in ("passwords.lst") do echo %%A
for /F "usebackq tokens=*" %%A in ("passwords.lst") do (
 rem %%A = a line in the file
 rem echo %%A
 set l=3
 set c=0
 for /f "delims=" %%1 in ('nthash-win64 /getntlmhash /input:%%A') do (
   rem set /a c+=1 && if "!c!" equ "%l%" echo %%1%
   set /a c+=1 && if "!c!" equ "%l%" set ret=%%1%
   rem above does not work anymore? dirty hack below
   set ret=%%1%
   if !input! == !ret! echo !input! = %%A
   set ret=""
 )
)