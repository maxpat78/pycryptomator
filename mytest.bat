@echo off
echo Testing cryptomator.py
rd /s /q mytest >nul
md mytest >nul
SET DNAME="/Nome di directory lungo, anzi, lunghissimo, ossia dal nome veramente lunghissimissimo e tale da venire codificato con oltre 255 caratteri dal codec Base64 di Cryptomator in modo da generare un doppio nome di file cifrato con hash"
SET FNAME="/Nome di file lungo, anzi, lunghissimo, ossia dal nome veramente lunghissimissimo e tale da venire codificato con oltre 255 caratteri dal codec Base64 di Cryptomator in modo da generare un doppio nome di file cifrato con hash.txt"
SET P=py -m pycryptomator --password=pippo
echo ++ Testing vault initialization
%P% --init mytest
echo ++ Testing master keys printing
%P% --print-keys words mytest
echo ++ Testing encryption
%P% mytest encrypt mytest.bat %FNAME%
echo ++ Testing directory making
%P% mytest makedirs %DNAME%
echo ++ Testing long names handling
%P% mytest encrypt mytest.bat %DNAME%/mytest.bat
echo ++ Testing linking
%P% mytest ln %DNAME%/mytest.bat /link_subdir_mytest.bat
echo ++ Testing listing
%P% mytest ls -r /
echo ++ Testing decryption to STDOUT
%P% mytest decrypt /link_subdir_mytest.bat -
echo ++ Testing alias
%P% mytest alias /link_subdir_mytest.bat
echo ++ Testing rename
%P% mytest mv /link_subdir_mytest.bat /same_link.bat
echo ++ Testing removing files and directory
%P% mytest rm /link_subdir_mytest.bat
%P% mytest rm /same_link.bat
%P% mytest rm %DNAME%
%P% mytest rm %DNAME%/mytest.bat
%P% mytest rm %DNAME%
%P% mytest ls
exit /b
%P% mytest encrypt cryptolib-develop /cryptolib-develop
%P% mytest ls
%P% mytest decrypt -f /cryptolib-develop T
%P% mytest backup dirids.zip
%P% mytest rm -f /cryptolib-develop
