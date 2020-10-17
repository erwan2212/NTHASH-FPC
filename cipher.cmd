@echo off

 setlocal ENABLEDELAYEDEXPANSION
 set input=%1
 rem echo %input%
 set l=3
 set c=0
 for /f "delims=" %%1 in ('NTHASH-win64.exe /stringtohexa /input:%input%') do (
   rem set /a c+=1 && if "!c!" equ "%l%" echo %%1%
   set /a c+=1 && if "!c!" equ "%l%" set ret=%%1%
   rem above no loger works, dirty hack below
   set ret=%%1%
 )
echo %ret% 
rem mode can be an algoid or hashid-algoid
rem example : RC4 or SHA1-RC4 
rem use set crypt_mode to cbc,ecb,ofb,cfb,cts to change the crypt_mode
rem default crypt_mode is ecb
set l=3
set c=0
rem keylen=16
echo RC2
 for /f "delims=" %%1 in ('NTHASH-win64.exe /getcipher /key:11223344556677881122334455667788 /mode:RC2 /input:%ret%') do (
   set /a c+=1 && if "!c!" equ "%l%" echo %%1%
   rem above no loger works, dirty hack below
   echo %%1
 )
set l=3
set c=0
rem keylen=16
echo RC4
 for /f "delims=" %%1 in ('NTHASH-win64.exe /getcipher /key:11223344556677881122334455667788 /mode:RC4 /input:%ret%') do (
   set /a c+=1 && if "!c!" equ "%l%" echo %%1%
   rem above no loger works, dirty hack below
   echo %%1
 )
set l=3
set c=0
rem keylen=8
rem KP_BLOCKLEN OK,8
echo DES - 0x6601 (default ECB)
 for /f "delims=" %%1 in ('NTHASH-win64.exe /getcipher /key:1122334455667788 /mode:DES /input:%ret%') do (
   set /a c+=1 && if "!c!" equ "%l%" echo %%1%
   rem above no loger works, dirty hack below
   echo %%1
 ) 
set l=3
set c=0
rem keylen=24
rem KP_BLOCKLEN OK,8
echo 3DES - 0x6603
 for /f "delims=" %%1 in ('NTHASH-win64.exe /getcipher /key:112233445566778811223344556677881122334455667788 /mode:3DES /input:%ret%') do (
   set /a c+=1 && if "!c!" equ "%l%" echo %%1%
   rem above no loger works, dirty hack below
   echo %%1
 )  
set l=3
set c=0
rem keylen=16
rem KP_BLOCKLEN OK,8
echo 3DES112 - 0x6609
 for /f "delims=" %%1 in ('NTHASH-win64.exe /getcipher /key:11223344556677881122334455667788 /mode:3DES112 /input:%ret%') do (
   set /a c+=1 && if "!c!" equ "%l%" echo %%1%
   rem above no loger works, dirty hack below
   echo %%1
 )   
set l=3
set c=0
rem keylen=32
rem KP_BLOCKLEN OK,16
rem echo AES - 0x6611
rem  for /f "delims=" %%1 in ('NTHASH-win64.exe /getcipher /key:1122334455667788112233445566778811223344556677881122334455667788 /mode:AES /input:%ret%') do (
rem    set /a c+=1 && if "!c!" equ "%l%" echo %%1%
rem  ) 
set l=3
set c=0
rem keylen=16
rem KP_BLOCKLEN OK,16
echo AES128 - 0x660E (default ECB)
 for /f "delims=" %%1 in ('NTHASH-win64.exe /getcipher /key:11223344556677881122334455667788 /mode:AES128 /input:%ret%') do (
   set /a c+=1 && if "!c!" equ "%l%" echo %%1%
   rem above no loger works, dirty hack below
   echo %%1
 )  
set l=3
set c=0 
rem keylen=32
rem KP_BLOCKLEN OK,16
echo AES256 - 0x6610 (default ECB)
 for /f "delims=" %%1 in ('NTHASH-win64.exe /getcipher /key:1122334455667788112233445566778811223344556677881122334455667788 /mode:AES256 /input:%ret%') do (
   set /a c+=1 && if "!c!" equ "%l%" echo %%1%
   rem above no loger works, dirty hack below
   echo %%1
 )  
