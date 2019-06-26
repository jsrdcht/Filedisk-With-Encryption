@echo off
echo Generation of a new Keyfile for your encrypted containers 
echo   Keyfile will be encrypted using a symmetric Key 
echo   (for public key use gpk.bat)
echo   gsk keyfile 
echo .


rem Generate a KeyFile with symetric encryption 
filedisk /rnd|gpg -c -a >%1


echo .
echo to create/mount the container using the created keyfile %1 type 
echo gm %1 containerfile [size]
echo it is recommended to copy the keyfile to a secure place like a usb stick
echo or a floppy drive. 



