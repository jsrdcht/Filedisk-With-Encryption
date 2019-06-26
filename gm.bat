@echo off
echo Mountig a container using gpg as drive
echo   please adjust for your needs
echo   gm keyfile container [extra Option for Filedisk]
echo .

type %1|gpg|filedisk /mount %2 %3 %4 /aes256




