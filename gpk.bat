@echo off
echo Generation of a new Keyfile for your encrypted containers 
echo   Keyfile will be encrypted for the given recipient (ie:your email address)
echo   (for symmetric keyfile encryption use gsk.bat)
echo   gpk keyfile [-r recipient] [-r 2ndRecipient]  
echo .


filedisk /rnd|gpg -e -a %2 %3 %4 %5 %6 %7>%1

type %1

echo .
echo to create/mount the container using the created keyfile %1 type 
echo gm %1 containerfile [size]
echo it is recommended to copy the keyfile to a secure place like a usb stick
echo or a floppy drive. 




