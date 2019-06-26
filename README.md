# Filedisk-With-Encryption
This is a virtual disk using file as the container(based on filedisk,a famous open source project) and AES as the encryption algorithm.

这是一个用文件来做虚拟磁盘容器的项目，基于开源项目filedisk，可在Windows xp server pack3下运行。  
使用方法见example.txt,如果要手动编译，可能需要较老的环境(项目中没有使用宽字符)，我用vs2013+winddk 8.0编译测试，驱动部分是没问题的，但是应用程序部分由于宽字符的问题不能成功运行。  
另外需要注意的是部分文件可能有缺失或者多余，但是所需全部文件都在，注意不对的地方手动更改即可（驱动部分缺失几个文件可以在应用程序文件夹中找到）
