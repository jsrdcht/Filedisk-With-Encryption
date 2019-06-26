@echo off
echo This will install the Cross-Crypt driver in your system
echo --- Press enter to continue --- or Ctrl-Break to stop
pause
echo .
echo trying to stop old driver
net stop filedisk
echo .
echo installing filedisk.reg
regedit filedisk.reg
echo .
echo copy new driver

copy filedisk.sys %systemroot%\system32\drivers\filedisk.sys /Y

echo trying to start driver
net start filedisk

echo ----
echo reboot your system if starting driver faild
pause


