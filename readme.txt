
   Stefan Scherrer:
	I added the SuSE linux TwoFish encryption to the FileDisk Project
	I will check with the orignial author if he wants to add my modifications
	or not. If not I will make a seperate project according to the GPL.

        currently the most recent version of encrypted filedisk can be found
	under http://www.scherrer.cc/crypt/

 	mfg,
	stefan@scherrer.cc

-----------------
    This is a virtual disk driver for Windows NT/2000/XP that uses
    one or more files to emulate physical disks.
    Copyright (C) 1999, 2000, 2001, 2002 Bo Brant�n.
    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.
    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.
    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

    The GNU General Public License is also available from:
    http://www.gnu.org/copyleft/gpl.html

    Windows and Windows NT are either registered trademarks or trademarks of
    Microsoft Corporation in the United States and/or other countries.

    Please send comments, corrections and contributions to bosse@acc.umu.se

    The most recent version of this program is available from:
    http://www.acc.umu.se/~bosse/

    Revision history:

   11. 2002-11-30
       Added ioctl to query information about mounted disk image files by
       request from developer of GUI.

   10. 2002-11-24
       Added a check so that FileDisk doesn't use compressed or encrypted
       images. For an explanation why this doesn't work see comment in the
       source code.

    9. 2002-08-26
       Corrected the share access for read-only FileDisk images.

    8. 2002-08-11
       Updated the control application to support UNC paths.
       Changed the handling of CD-ROM device objects to avoid some problems on
       Windows XP.
       Corrected the handling of file sizes so that FileDisk images can be
       sparse files.

    7. 2002-02-28
       Added support for CD-images.

    6. 2002-01-21
       Added support for impersonation so that FileDisk images can be stored
       on network drives.

    5. 2002-01-18
       Updated for Windows XP by Robert A. Rose.

    4. 2001-07-08
       Formating to FAT on Windows 2000 now works.

    3. 2001-05-14
       Corrected the error messages from the usermode control application.

    2. 2000-03-15
       Added handling of IOCTL_DISK_CHECK_VERIFY to make the driver work on
       Windows 2000 (tested on beta 3, build 2031). Formating to FAT still
       doesn't work but formating to NTFS does.

    1. 1999-06-09
       Initial release.
