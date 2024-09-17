@echo off
echo Testing cryptomator.py (vault initialization, master keys printing, encryption, long names handling, listing)
rd /s /q mytest >nul
md mytest >nul
cryptomator.py --password=pippo --init mytest
cryptomator.py --password=pippo --print-keys words mytest
cryptomator.py --password=pippo mytest encrypt mytest.bat "/Nome di file lungo, anzi, lunghissimo, ossia dal nome veramente lunghissimissimo e tale da venire codificato con oltre 255 caratteri dal codec Base64 di Cryptomator in modo da generare un doppio nome di file cifrato con hash.txt"
cryptomator.py --password=pippo mytest makedirs "/Nome di directory lungo, anzi, lunghissimo, ossia dal nome veramente lunghissimissimo e tale da venire codificato con oltre 255 caratteri dal codec Base64 di Cryptomator in modo da generare un doppio nome di file cifrato con hash"
cryptomator.py --password=pippo mytest encrypt mytest.bat "/Nome di directory lungo, anzi, lunghissimo, ossia dal nome veramente lunghissimissimo e tale da venire codificato con oltre 255 caratteri dal codec Base64 di Cryptomator in modo da generare un doppio nome di file cifrato con hash/mytest.bat"
cryptomator.py --password=pippo mytest ls -r /
