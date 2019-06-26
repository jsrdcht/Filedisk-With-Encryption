filedisk /umount
if ERRORLEVEL 1 GOTO end

net stop filedisk
copy ..\obj\i386\filedisk.sys c:\windows\system32\drivers\filedisk.sys
copy ..\obj\i386\filedisk.sys ..\..
net start filedisk
if ERRORLEVEL 1 shutdown -r -c "Reboot required"
:end



