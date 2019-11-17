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
echo MD2
 for /f "delims=" %%1 in ('NTHASH-win64.exe /gethash /mode:MD2 /input:%ret%') do (
   set /a c+=1 && if "!c!" equ "%l%" echo %%1%
 )
set l=2
set c=0
echo MD4
 for /f "delims=" %%1 in ('NTHASH-win64.exe /gethash /mode:MD4 /input:%ret%') do (
   set /a c+=1 && if "!c!" equ "%l%" echo %%1%
 )
set l=2
set c=0
echo MD5
 for /f "delims=" %%1 in ('NTHASH-win64.exe /gethash /mode:MD5 /input:%ret%') do (
   set /a c+=1 && if "!c!" equ "%l%" echo %%1%
 )
set l=2
set c=0
echo SHA1
 for /f "delims=" %%1 in ('NTHASH-win64.exe /gethash /mode:SHA1 /input:%ret%') do (
   set /a c+=1 && if "!c!" equ "%l%" echo %%1%
 )
set l=2
set c=0
echo SHA256
 for /f "delims=" %%1 in ('NTHASH-win64.exe /gethash /mode:SHA256 /input:%ret%') do (
   set /a c+=1 && if "!c!" equ "%l%" echo %%1%
 )
set l=2
set c=0
echo SHA512
 for /f "delims=" %%1 in ('NTHASH-win64.exe /gethash /mode:SHA512 /input:%ret%') do (
   set /a c+=1 && if "!c!" equ "%l%" echo %%1%
 )

