/*
    Control program for a virtual disk driver for Windows NT/2000/XP.
    Copyright (C) 1999, 2000, 2001, 2002 Bo Brantén.
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

   modified by Stefan Scherrer to add crypt support

*/

#include <windows.h>
#include <winioctl.h>
#include <stdio.h>
#include <stdlib.h>
#include <Wincrypt.h>
#include "filedisk.h"
#include "twofish.h"
#include "rmd160.h"
#include "tom.h"
#include "sha512.h"



int FileDiskSyntax(void)
{
    fprintf(stderr, "syntax:\n");
    fprintf(stderr, "filedisk /mount  <filename> [size[k|M|G] | /ro | /cd] [<drive:>] [Encryption]\n");
    fprintf(stderr, "filedisk /umount [<drive:>]\n");
    fprintf(stderr, "filedisk /status [<drive:>]\n");
    fprintf(stderr, "filedisk /encrypt <filename_plain> <filename_encryped> [Encryption]\n");
    fprintf(stderr, "filedisk /decrypt <filename_crypt> <filename_plain> [Encryption]\n");
	fprintf(stderr, "filedisk /rnd [/m]  (Generate Random key)\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "filename formats:\n");
    fprintf(stderr, "  c:\\path\\filedisk.img\n");
    fprintf(stderr, "  \\Device\\Harddisk0\\Partition1\\path\\filedisk.img\n");
    fprintf(stderr, "  \\\\server\\share\\path\\filedisk.img\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "Encryption \n");
    fprintf(stderr, "/2f:key encrypt / decrypt with twofish using the given key\n");
    fprintf(stderr, "/aes128:key encrypt / decrypt with AES128 using the given key\n");
    fprintf(stderr, "/aes256:key encrypt / decrypt with AES256 using the given key\n");
    fprintf(stderr, "/aes192:key encrypt / decrypt with AES192 using the given key\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "example:\n");
    fprintf(stderr, "filedisk /mount  c:\\temp\\filedisk.img 8M /aes256\n");
    fprintf(stderr, "filedisk /mount  c:\\temp\\cdimage.iso /cd g:\n");
    fprintf(stderr, "filedisk /umount f:\n");
    fprintf(stderr, "filedisk /umount\n");

    return -1;
}

void PrintLastError(char* Prefix)
{
    LPVOID lpMsgBuf;

    FormatMessage(
        FORMAT_MESSAGE_ALLOCATE_BUFFER |
        FORMAT_MESSAGE_FROM_SYSTEM |
        FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL,
        GetLastError(),
        0,
        (LPTSTR) &lpMsgBuf,
        0,
        NULL
        );

    fprintf(stderr, "%s %s", Prefix, (LPTSTR) lpMsgBuf);

    LocalFree(lpMsgBuf);
}

int
FileDiskMount(
    int                     DeviceNumber,
    POPEN_FILE_INFORMATION  OpenFileInformation,
    char                    DriveLetter,
    BOOLEAN                 CdImage
)
{
    char    VolumeName[] = "\\\\.\\ :";
    char    DeviceName[255];
    HANDLE  Device;
    DWORD   BytesReturned;

    VolumeName[4] = DriveLetter;

    Device = CreateFile(
        VolumeName,
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        OPEN_EXISTING,
        FILE_FLAG_NO_BUFFERING,
        NULL
        );

    if (Device != INVALID_HANDLE_VALUE)
    {
        SetLastError(ERROR_BUSY);
        PrintLastError(&VolumeName[4]);
        return -1;
    }

    if (CdImage)
    {
        sprintf(DeviceName, DEVICE_NAME_PREFIX "Cd" "%u", DeviceNumber);
    }
    else
    {
        sprintf(DeviceName, DEVICE_NAME_PREFIX "%u", DeviceNumber);
    }

    if (!DefineDosDevice(
        DDD_RAW_TARGET_PATH,
        &VolumeName[4],
        DeviceName
        ))
    {
        PrintLastError(&VolumeName[4]);
        return -1;
    }

    Device = CreateFile(
        VolumeName,
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        OPEN_EXISTING,
        FILE_FLAG_NO_BUFFERING,
        NULL
        );

    if (Device == INVALID_HANDLE_VALUE)
    {
        PrintLastError(&VolumeName[4]);
        DefineDosDevice(DDD_REMOVE_DEFINITION, &VolumeName[4], NULL);
        return -1;
    }

    if (!DeviceIoControl(
        Device,
        IOCTL_FILE_DISK_OPEN_FILE,
        OpenFileInformation,
        sizeof(OPEN_FILE_INFORMATION) + OpenFileInformation->FileNameLength - 1,
        NULL,
        0,
        &BytesReturned,
        NULL
        ))
    {
		printf("Fn: %s\n",OpenFileInformation->FileName);
        PrintLastError("FileDisk:");
        DefineDosDevice(DDD_REMOVE_DEFINITION, &VolumeName[4], NULL);
        return -1;
    }

    return 0;
}

int FileDiskUmount2(char *VolumeName)
{
    char DriveLetter[4];
    HANDLE  Device;
    DWORD   BytesReturned;
    POPEN_FILE_INFORMATION OpenFileInformation;

	strcpy(DriveLetter," :");

    Device = CreateFile(
        VolumeName,
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        OPEN_EXISTING,
        FILE_FLAG_NO_BUFFERING,
        NULL
        );

    if (Device == INVALID_HANDLE_VALUE)
    {
        //PrintLastError(&VolumeName[4]);
        return -3;
    }

    	OpenFileInformation = malloc(sizeof(OPEN_FILE_INFORMATION) + MAX_PATH);

		if (!DeviceIoControl(
					Device,
					IOCTL_FILE_DISK_QUERY_FILE,
					NULL,
					0,
					OpenFileInformation,
					sizeof(OPEN_FILE_INFORMATION) + MAX_PATH,
					&BytesReturned,
					NULL
					))
		{
			//PrintLastError(VolumeName);
			free(OpenFileInformation);
			CloseHandle(Device);
			return -2;
		}
	DriveLetter[0] = OpenFileInformation->DriveLetter;

	free(OpenFileInformation);
	if (!DriveLetter[0]) {
		CloseHandle(Device);
		return 0;
	}



    if (!DeviceIoControl(
        Device,
        FSCTL_LOCK_VOLUME,
        NULL,
        0,
        NULL,
        0,
        &BytesReturned,
        NULL
        ))
    {
        PrintLastError("Ignored:");
        //return -1;
    }

    if (!DeviceIoControl(
        Device,
        IOCTL_FILE_DISK_CLOSE_FILE,
        NULL,
        0,
        NULL,
        0,
        &BytesReturned,
        NULL
        ))
    {
        PrintLastError("FileDisk:");
        return -1;
    }

    if (!DeviceIoControl(
        Device,
        FSCTL_DISMOUNT_VOLUME,
        NULL,
        0,
        NULL,
        0,
        &BytesReturned,
        NULL
        ))
    {
        PrintLastError(VolumeName);
        return -1;
    }

    if (!DeviceIoControl(
        Device,
        FSCTL_UNLOCK_VOLUME,
        NULL,
        0,
        NULL,
        0,
        &BytesReturned,
        NULL
        ))
    {
        //PrintLastError("Ignored:");
        //return -1;
    }

    CloseHandle(Device);


    if (!DefineDosDevice(
        DDD_REMOVE_DEFINITION,
        DriveLetter,
        NULL
        ))
    {
        PrintLastError(DriveLetter);
        return -1;
    }

	printf("%s: unmounted\n",DriveLetter);
    return 0;
}


int FileDiskUmount(char DriveLetter)
{
	    char VolumeName[60] = "\\\\.\\ :";
		int i;



		if (DriveLetter) {
			VolumeName[4] = DriveLetter;

			i= FileDiskUmount2(VolumeName);
			if (i) PrintLastError("Unmount´");
			return i;
		}
		for (i=0;i<20;i++) {
			sprintf(VolumeName,"\\\\.\\FileDisk%d",i);
			if (FileDiskUmount2(VolumeName) == -3) break;
		}
		for (i=0;i<20;i++) {
			sprintf(VolumeName,"\\\\.\\FileDiskCd%d",i);
			if (FileDiskUmount2(VolumeName) == -3) break;
		}
		return 0;
}


int PrintInfo(char *VolumeName) {
	HANDLE                  Device;
	POPEN_FILE_INFORMATION  OpenFileInformation;
	DWORD                   BytesReturned;

	Device = CreateFile(
		VolumeName,
		GENERIC_READ,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		NULL,
		OPEN_EXISTING,
		FILE_FLAG_NO_BUFFERING,
		NULL
		);

	if (Device == INVALID_HANDLE_VALUE)
	{
		//PrintLastError(VolumeName);
		return -1;
	}

	OpenFileInformation = malloc(sizeof(OPEN_FILE_INFORMATION) + MAX_PATH);

	if (!DeviceIoControl(
				Device,
				IOCTL_FILE_DISK_QUERY_FILE,
				NULL,
				0,
				OpenFileInformation,
				sizeof(OPEN_FILE_INFORMATION) + MAX_PATH,
				&BytesReturned,
				NULL
				))
	{
		//PrintLastError(VolumeName);
		free(OpenFileInformation);
		CloseHandle(Device);
		return -2;
	}

	if (BytesReturned < sizeof(OPEN_FILE_INFORMATION))
	{
		SetLastError(ERROR_INSUFFICIENT_BUFFER);
		PrintLastError(&VolumeName[4]);
		CloseHandle(Device);
		return -2;
	}

	printf("%c: -> %.*s Size: %I64u bytes %s\n",
				OpenFileInformation->DriveLetter,
				OpenFileInformation->FileNameLength,
				OpenFileInformation->FileName,
				OpenFileInformation->FileSize,
				OpenFileInformation->ReadOnly ? ", ReadOnly" : ""
				);

	free(OpenFileInformation);
	CloseHandle(Device);
	return 0;

}

int FileDiskStatus(char DriveLetter)
{
    char VolumeName[60] = "\\\\.\\ :";
	int i;



	if (DriveLetter) {
		VolumeName[4] = DriveLetter;

		return PrintInfo(VolumeName);
	}
	for (i=0;i<20;i++) {
		sprintf(VolumeName,"\\\\.\\FileDisk%d",i);
		if (PrintInfo(VolumeName) == -1) break;
	}
	for (i=0;i<20;i++) {
		sprintf(VolumeName,"\\\\.\\FileDiskCd%d",i);
		if (PrintInfo(VolumeName) == -1) break;
	}

    return 0;
}


char *cvfile(char *c)
{
	static char buf[MAX_PATH+1];

	if (c[0] == '\\') {
		if (c[1] == '\\' && c[2] != '.') {
	        // \\server\share\path\filedisk.img
             strcpy(buf, "\\.\\UNC");
             strcat(buf,c+ 1);
         } else {  // \Device\Harddisk0\Partition1\path\filedisk.img
            return c;
         }
	} else {	// c:\path\filedisk.img
        strcpy(buf, "\\\\.\\");
        strcat(buf, c);
    }
    return buf;
}

void AESEncryptCBC(unsigned char *datap,DWORD anz,ulong32 devSect[4],symmetric_key *key)
{
    ulong32 iv[4];
    int ivCounter = 0;
    int cnt = anz >> 4;

    do {
        if(!ivCounter) {
			memcpy(iv,devSect,16);
            if(!++devSect[0] && !++devSect[1] && !++devSect[2]) devSect[3]++;
        }
        ivCounter++;
        ivCounter &= 31;
        iv[0] ^= *((ulong32 *)(&datap[ 0]));
        iv[1] ^= *((ulong32 *)(&datap[ 4]));
        iv[2] ^= *((ulong32 *)(&datap[ 8]));
        iv[3] ^= *((ulong32 *)(&datap[12]));
        rijndael_ecb_encrypt((unsigned char *)iv,datap,key);
        //aes_encrypt(&ctx, (unsigned char *)(&iv[0]), datap);
        memcpy(&iv[0], datap, 16);
        datap += 16;
    } while(--cnt);
}

void AESDecryptCBC(unsigned char *datap,DWORD anz,ulong32 devSect[4],symmetric_key *key)
{
    ulong32 iv[8];
    int ivCounter = 0;
    int cnt = anz >> 4;

    do {
		if(!ivCounter) {
			memcpy(iv,devSect,16);
		    if(!++devSect[0] && !++devSect[1] && !++devSect[2]) devSect[3]++;
		}

        ivCounter++;
        ivCounter &= 31;
        memcpy(&iv[4], datap, 16);
        rijndael_ecb_decrypt(datap,datap,key);

        *((ulong32 *)(&datap[ 0])) ^= iv[0];
        *((ulong32 *)(&datap[ 4])) ^= iv[1];
        *((ulong32 *)(&datap[ 8])) ^= iv[2];
        *((ulong32 *)(&datap[12])) ^= iv[3];
        memcpy(&iv[0], &iv[4], 16);
        datap += 16;
    } while(--cnt);
}



int EnDecrypt(int enc,POPEN_FILE_INFORMATION ka,char *fin,char *fout)
{
	HANDLE inH;
	HANDLE outH;
	int err = 1;
	static unsigned char buf[128*512];
	DWORD anz;
	DWORD wr;
	long tot = 0;


	union {
		fish2_key fk;
		symmetric_key aes;
	} k;
	char tmp[64];
	ulong32 devSect[4];

	char *obuf;

	obuf = buf;

	memset(devSect,0,sizeof(devSect));

	inH = CreateFile(cvfile(fin),
				GENERIC_READ,FILE_SHARE_READ|FILE_SHARE_WRITE,
				NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL|FILE_FLAG_SEQUENTIAL_SCAN,NULL);
    if (inH == INVALID_HANDLE_VALUE)
    {
        PrintLastError(cvfile(fin));
        return -1;
    }
	outH = CreateFile(cvfile(fout),
				GENERIC_WRITE,FILE_SHARE_READ|FILE_SHARE_WRITE,
				NULL,OPEN_ALWAYS,FILE_ATTRIBUTE_NORMAL|FILE_FLAG_SEQUENTIAL_SCAN,NULL);

    if (outH == INVALID_HANDLE_VALUE)
    {
		CloseHandle(inH);
        PrintLastError(cvfile(fout));
        return -1;
    }
    memset(&k,0,sizeof(k));

    switch (ka->KeyType) {
		case 1:		//2fish
			memcpy(k.fk.key,ka->Key[0],ka->KeyLength);
			k.fk.keyLen = 20<<3;
			init_key(&k.fk);
			break;
		case 2:		//AES256
			if (rijndael_setup(ka->Key[0], 32, 0, &k.aes)) {
				PrintLastError("AES256 KeySetup faild");
			}
			break;
		case 3:		//AES128
			if (rijndael_setup(ka->Key[0], 16, 0, &k.aes)) {
				PrintLastError("AES128 KeySetup faild");
			}
			break;
		case 4:		//AES192
			if (rijndael_setup(ka->Key[0], 24, 0, &k.aes)) {
				PrintLastError("AES192 KeySetup faild");
			}
			break;
	}

	while (1) {
		int i;

		if (!ReadFile(inH,buf,sizeof(buf),&anz,NULL)) {
			PrintLastError("Read error");
			break;
		}
		//512 Byte padding
		while (anz & 0x1ff) buf[anz++] = 0;

		tot += anz;

		printf("Reading %3.2f MB\r",(double)tot / (1024.0*1024.0));
		if (anz == 0) {
			printf("OK %3.2f MB\r",(double)tot / (1024.0*1024.0));
			err = 0;
			break;
		}

		switch (ka->KeyType) {
		case 0:
			break;
		case 1:
			if (enc) {
				blockEncrypt_CBC(&k.fk,buf,obuf,anz);
			} else {
				blockDecrypt_CBC(&k.fk,buf,obuf,anz);

			}
			break;
		case 2:	//AES256
		case 3:	//AES128
		case 4:	//AES192
			if (enc) {
				AESEncryptCBC(buf,anz,devSect,&k.aes);
			} else {
				AESDecryptCBC(buf,anz,devSect,&k.aes);
			}
			break;

		}

		if (!WriteFile(outH,obuf,anz,&wr,NULL)) {
			PrintLastError("\nWrite Error");
			err = 1;
			break;
		}
		if (wr != anz) {
			PrintLastError("\nWrite Error");
			err = 1;
			break;
		}
		if (anz < sizeof(buf)) {
			printf("\nOK %3.2f MB\n",(double)tot / (1024.0*1024.0));
			err = 0;
			break;
		}

	}


    CloseHandle(outH);
   	CloseHandle(inH);
   	memset(&k,0,sizeof(k));		//kill keys
   	return err;

}

int PrintRandom(int anz)
{
	int i,i2;
	HCRYPTPROV hProvider = 0;
	BYTE randomBytes[60];

	if (!CryptAcquireContext(&hProvider, 0, 0, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
		PrintLastError("CryptAcquireContext:");
		exit(1);
	}


	for (i=0;i<anz;i++) {

		if (!CryptGenRandom(hProvider, sizeof(randomBytes), randomBytes)) {
			CryptReleaseContext(hProvider,0);
			PrintLastError("CryptAcquireContext:");
			exit(1);
		}
		for (i2= 0;i2<sizeof(randomBytes);i2++) {
			printf("%c",0x20+(randomBytes[i2] & 0x3f));
		}
		printf("\n");
	}
	CryptReleaseContext(hProvider,0);
	return 0;
}

void AddKey(POPEN_FILE_INFORMATION  ka,char *key,int len)
{
	RMD160_CTX rctx;

	if (ka->KeyNum >= MAX_KEYS) return;

    switch (ka->KeyType) {
		case 1:		//2fish
			ka->KeyLength=20;

			RMD160Init(&rctx);
			RMD160Update(&rctx,key,len);
			RMD160Final(ka->Key[ka->KeyNum++],&rctx);
			break;
		case 2:		//AES256
			ka->KeyLength=32;
			sha512_hash_buffer(key,len,ka->Key[ka->KeyNum++],ka->KeyLength);
			break;
		case 3:		//AES128
			ka->KeyLength=16;
			sha256_hash_buffer(key,len,ka->Key[ka->KeyNum++],ka->KeyLength);
			break;
		case 4:		//AES192
			ka->KeyLength=24;
			sha384_hash_buffer(key,len,ka->Key[ka->KeyNum++],ka->KeyLength);
			break;
	}

}

#define MAX_KEY_LENGTH 500

USHORT ReadKey(POPEN_FILE_INFORMATION ka,int keys,int test) {
	 DWORD dwConsoleMode;
	HANDLE hConIn;
	char buf[MAX_KEY_LENGTH+20];
	int anz,i;

	 hConIn = GetStdHandle(STD_INPUT_HANDLE);
     GetConsoleMode(hConIn, &dwConsoleMode);
     dwConsoleMode &= ~(ENABLE_ECHO_INPUT);		//
	 dwConsoleMode |= (ENABLE_LINE_INPUT);
     SetConsoleMode(hConIn,dwConsoleMode);

	for (i = 0;i<keys;i++) {
		memset(buf,0,sizeof(buf));
		fprintf(stdout,"%d.Passphrase:",i+1);
		if (fgets(buf,MAX_KEY_LENGTH+19,stdin) == NULL) break;	//eof
		anz = strlen(buf);
		if (buf[anz-1] == '\r' || buf[anz-1] == '\n') buf[--anz]=0;

		if (anz == 0) {
			fprintf(stderr,"ERROR: No key supplied exit\n");
			exit(1);
		}
		if (anz > MAX_KEY_LENGTH) {
			fprintf(stderr,"Sorry Key too long\n");
			exit(1);
		}
		if (test) {
			char buf2[MAX_KEY_LENGTH+20];
			memset(buf2,0,sizeof(buf2));

			fprintf(stdout,"\rRetype %d.Passphrase:",i+1);
			if (fgets(buf2,MAX_KEY_LENGTH+19,stdin) == NULL) break;	//eof
			anz = strlen(buf2);
			if (buf2[anz-1] == '\r' || buf2[anz-1] == '\n') buf2[--anz]=0;

			if (strcmp(buf,buf2)) {
				memset(buf,0,sizeof(buf));		//kill key
				memset(buf2,0,sizeof(buf2));		//kill key
				fprintf(stderr,"Passwords do not match\n");
				exit(1);
			}
			memset(buf2,0,sizeof(buf2));		//kill key

		}
		printf("\n");
		AddKey(ka,buf,anz);
		memset(buf,0,sizeof(buf));		//kill key

		if (anz < 20) fprintf(stderr,"WARNING: Key will be to short for linux (min 20 chars) %d\n",anz);
	}
	if (i<keys) {
		fprintf(stderr,"ERROR: %d keys missing exit\n",keys-i);
		exit(1);
	}

	return 0;
}

int DevUsed(char *VolumeName)
{
	HANDLE                  Device;
	POPEN_FILE_INFORMATION  OpenFileInformation;
	DWORD                   BytesReturned;

	Device = CreateFile(
		VolumeName,
		GENERIC_READ,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		NULL,
		OPEN_EXISTING,
		FILE_FLAG_NO_BUFFERING,
		NULL
		);

	if (Device == INVALID_HANDLE_VALUE)
	{
		//PrintLastError(VolumeName);
		return -1;
	}

	OpenFileInformation = malloc(sizeof(OPEN_FILE_INFORMATION) + MAX_PATH);

	if (!DeviceIoControl(
				Device,
				IOCTL_FILE_DISK_QUERY_FILE,
				NULL,
				0,
				OpenFileInformation,
				sizeof(OPEN_FILE_INFORMATION) + MAX_PATH,
				&BytesReturned,
				NULL
				))
	{
		//PrintLastError(VolumeName);
		free(OpenFileInformation);
		CloseHandle(Device);
		return 0;		//Not used
	}

	free(OpenFileInformation);
	CloseHandle(Device);
	return 1;		//used

}

int GetFreeDev(BOOLEAN CdImage)
{
	int i,stat;
	char VolumeName[50];

	if (!CdImage) {
		for (i=0;i<20;i++) {
			sprintf(VolumeName,"\\\\.\\FileDisk%d",i);
			stat = DevUsed(VolumeName);
			if (stat <= -1) return -1;	//Not found
			if (!stat) return  i;		//Not used
		}
	} else {
		for (i=0;i<20;i++) {
			sprintf(VolumeName,"\\\\.\\FileDiskCd%d",i);
			stat = DevUsed(VolumeName);
			if (stat <= -1) return -1;	//Not found
			if (!stat) return  i;		//Not used
		}
	}
	return -1;

}

//Return next free DosDevice
char GetFreeDrive()
{
	int i;
	DWORD ld = GetLogicalDrives();


	if (ld == 0) return (char)0;
	for (i=3;i<26;i++) {
		if ((ld & (1<<i)) == 0) return 'A'+i;
	}
	return 0;		//No free drive
}

int __cdecl main(int argc, char* argv[])
{
    char*                   Command;
    int                     DeviceNumber;
    char*                   FileName;
    char*                   Option;
    char                    DriveLetter;
    BOOLEAN                 CdImage = FALSE;
    BOOLEAN                 ReadOnly = FALSE;
    POPEN_FILE_INFORMATION  OpenFileInformation;
    int i;
    char *par[10];
    int pind=0;
    OPEN_FILE_INFORMATION  ka;
    int multiplekey = 0;
    int testkey = 0;

    memset(par,0,sizeof(par));
    memset(&ka,0,sizeof(ka));


//	printf("sha_test %d \n",sha512_test());
	//printf("aes_test %d \n",aes_test());


    for (i = 2;i<argc;i++) {
		char *c;

		if (!strncmp(argv[i],"/2f",3)) {
			ka.KeyType = 1;
			c = strchr(argv[i],':');
			if (c) AddKey(&ka,c+1,strlen(c+1));
		} else if (!strncmp(argv[i],"/aes256",7)) {
			ka.KeyType = 2;
			c = strchr(argv[i],':');
			if (c) AddKey(&ka,c+1,strlen(c+1));

		} else if (!strncmp(argv[i],"/aes128",7)) {
			ka.KeyType = 3;
			c = strchr(argv[i],':');
			if (c) AddKey(&ka,c+1,strlen(c+1));
		} else if (!strncmp(argv[i],"/aes192",7)) {
			ka.KeyType = 4;
			c = strchr(argv[i],':');
			if (c) AddKey(&ka,c+1,strlen(c+1));
		} else if (!strcmp(argv[i],"/cd")) {
			ReadOnly = TRUE;
			CdImage = TRUE;
		} else if (!strcmp(argv[i],"/ro")) {
			ReadOnly = TRUE;
		} else if (!strcmp(argv[i],"/m")) {
			multiplekey = 1;
		} else if (!strcmp(argv[i],"/t")) {
			testkey = 1;
		} else if (!strncmp(argv[i],"/",1)) {
			return FileDiskSyntax();
		} else {
			par[pind++] = argv[i];
		}
	}
	//if we need en/decryption we will need keys
	if (ka.KeyType) {
		if (multiplekey) {
			if (ka.KeyNum < 64) ReadKey(&ka,64-ka.KeyNum,testkey);
		} else {
			if (ka.KeyNum < 1) ReadKey(&ka,1-ka.KeyNum,testkey);
		}
	}

	if (argc < 2) {
		return FileDiskSyntax();
	}
    Command = argv[1];


	if (!strcmp(Command,"/rnd")) {
		PrintRandom(multiplekey ? 64 : 1);
		return 0;
	} else if (!strcmp(Command, "/mount") && pind >= 1) {
		char full[_MAX_PATH];

		if (par[0][0] != '\\' && par[0][1] != ':' && _fullpath( full, par[0], _MAX_PATH ) != NULL ) {
			FileName = full;
		} else {
			FileName = par[0];
		}

        DeviceNumber = GetFreeDev(CdImage);
        if (DeviceNumber < 0) {
			fprintf(stderr,"No free Filedisk Device\n");
			return -1;
		}


        if (strlen(FileName) < 2)
        {
            return FileDiskSyntax();
        }

        OpenFileInformation =
            malloc(sizeof(OPEN_FILE_INFORMATION) + strlen(FileName) + 7);

        memset(
            OpenFileInformation,
            0,
            sizeof(OPEN_FILE_INFORMATION) + strlen(FileName) + 7
            );

		memcpy(OpenFileInformation,&ka,sizeof(ka));		//CopyGenerated keys

		OpenFileInformation->version = CCVERSION;

        if (FileName[0] == '\\')
        {
            if (FileName[1] == '\\')
                // \\server\share\path\filedisk.img
            {
                strcpy(OpenFileInformation->FileName, "\\??\\UNC");
                strcat(OpenFileInformation->FileName, FileName + 1);
            }
            else
                // \Device\Harddisk0\Partition1\path\filedisk.img
            {
                strcpy(OpenFileInformation->FileName, FileName);
            }
        }
        else
            // c:\path\filedisk.img
        {
            strcpy(OpenFileInformation->FileName, "\\??\\");
            strcat(OpenFileInformation->FileName, FileName);
        }

        OpenFileInformation->FileNameLength =
            (USHORT) strlen(OpenFileInformation->FileName);


		OpenFileInformation->ReadOnly = ReadOnly;
		if (pind > 1 && par[1][0] <= '9') {	//FileSize
            Option = par[1];


            if (Option[strlen(Option) - 1] == 'G') {
                 OpenFileInformation->FileSize.QuadPart =
                      _atoi64(Option) * 1024 * 1024 * 1024;
            } else if (Option[strlen(Option) - 1] == 'M') {
                 OpenFileInformation->FileSize.QuadPart =
                        _atoi64(Option) * 1024 * 1024;
            } else if (Option[strlen(Option) - 1] == 'k') {
                OpenFileInformation->FileSize.QuadPart =
                     _atoi64(Option) * 1024;
            } else {
                  OpenFileInformation->FileSize.QuadPart =
                      _atoi64(Option);
            }
        }
        if (pind > 1 && par[1][0] >= 'A' && par[1][1] == ':') {
			DriveLetter = par[1][0];
		} else if (pind > 2 && par[2][0] >= 'A' && par[2][1] == ':') {
			DriveLetter = par[2][0];
		} else {
			DriveLetter = GetFreeDrive();
		}
		OpenFileInformation->DriveLetter  = DriveLetter;
        i = FileDiskMount(DeviceNumber, OpenFileInformation, DriveLetter, CdImage);

        if (!i) printf("%c: -> %s mounted\n",DriveLetter,OpenFileInformation->FileName);
        memset(&ka,0,sizeof(ka));		//kill keys
        memset(OpenFileInformation,0,sizeof(ka));
        return i;
    }
    else if (!strcmp(Command, "/umount"))
    {
		memset(&ka,0,sizeof(ka));		//kill keys
		DriveLetter = 0;
        if (pind >= 1) DriveLetter = par[0][0];
        return FileDiskUmount(DriveLetter);
    }
    else if (!strcmp(Command, "/status"))
    {
		memset(&ka,0,sizeof(ka));		//kill keys
		DriveLetter = 0;
		if (pind) DriveLetter = par[0][0];
		return FileDiskStatus(DriveLetter);
    }
    else if (pind >= 2 && !strcmp(Command,"/encrypt"))
    {
		i = EnDecrypt(1,&ka,par[0],par[1]);
		memset(&ka,0,sizeof(ka));		//kill keys
		return i;

	}
	else if (pind >= 2 && !strcmp(Command,"/decrypt"))
	{
		i = EnDecrypt(0,&ka,par[0],par[1]);
		memset(&ka,0,sizeof(ka));		//kill keys
		return i;

	}
    else
    {
		memset(&ka,0,sizeof(ka));		//kill keys
        return FileDiskSyntax();
    }
}
