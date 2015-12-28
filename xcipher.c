#include "sys_xcrypt.h"
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <sys/syscall.h>
#include <openssl/md5.h>
#ifndef __NR_xcrypt
#error xcrypt system call not defined
#endif

/*
This is the main function of user space which takes the following arguments from user at command line:
1. Encryption or Decryption using -e and -d flag respectively.
2. Password using -p flag.
3. Input File name.
4. Output File name.

If all arguments are valid, then it calls the system call sys_xcrypt otherwise return an error.
After calling system call, displays proper error message.
*/
int main(int argc, char *argv[])
{
	//Declaring variables for storing user data, md5 key and error status.
	int isEncrypt=0, isDecrypt=0, isPwd=0;	
	char *pwd; 	
	sysargs sys; 
	int ch, rc; 
	unsigned char hash[MD5_DIGEST_LENGTH];

	long validCmd = 0;

	memset(&sys, 0, sizeof(sysargs));

	//Accessing command line arguments by flags specified.
	while((ch = getopt(argc, argv, "p:edh")) != -1)	
	{
		switch(ch)
		{
			case 'p':
				isPwd = 1;
				pwd = optarg;
				break;
			
			case 'e':
                                isEncrypt = 1;
                                break;

			case 'd':
                                isDecrypt = 1;
                                break;

			case 'h':
				fprintf(stdout, "Usage: %s {-p PASSWORD} {-e|-d} [-h HELP] infile outfile\n", argv[0]);
				fprintf(stdout, "-p : Specify Password (Min: 6 characters)\n");
				fprintf(stdout, "-e : Specify Encryption\n");
				fprintf(stdout, "-d : Specify Decryption\n");
				fprintf(stdout, "-h : Display help message\n");
				fprintf(stdout, "infile: Input File\n");
				fprintf(stdout, "outfile: Output File\n");
				return -1;

			case '?':
				validCmd = -1;
				break;										
		}
	}


	//Checking for any invalid argument specified.
	if(validCmd == -1 || (isEncrypt == isDecrypt) || isPwd == 0 || (optind+2 != argc))
	{
		fprintf(stderr,"Usage: %s {-p PASSWORD} {-e|-d} [-h HELP] infile outfile\n", argv[0]);
		return -1;
	}

	//Checking if password is less than 6 characters.
	if(strlen(pwd)<6)
	{
		fprintf(stderr,"Usage: Password should be atleast 6 characters long!\n");
		return -1;
	}

	//Storing input and output file.
	sys.input_file = argv[optind];
	sys.output_file = argv[optind+1];

	//Generating MD5 hash of the user password.
	MD5((const unsigned char *)pwd, strlen(pwd), hash);

	sys.key_buffer = (char *) hash;
	sys.keylength = MD5_DIGEST_LENGTH;
	sys.flags = (isEncrypt == 1)? 1:0;
	
	//System call to sys_xcrypt 
	rc = syscall(__NR_xcrypt, &sys);

	//Checking for error returned and displaying corresponding error status.
	if (rc != 0)
	{
		switch(errno)
		{
			case 1: //EPERM
				printf("Key mismatched! Operation not permitted!\n");
				break;

			case 2: //ENOENT
				printf("File does not exist!\n");
				break;

			case 5: //EIO
				printf("Error in reading file : %s \n", sys.input_file);
				break;

			case 9: //EBADF
				printf("Bad File: %s\n", sys.input_file);
				break;

			case 12: //ENOMEM
				printf("Not enough memory available!\n");
				break;

			case 14: //EFAULT
				printf("Invalid parameters, null pointers or encryption/decryption failed!\n");
				break;

			case 22: //EINVAL
				printf("Input and Output File can not be same! or Hash Conversion failed due to bad arguments!\n");
				break;

			case 30: //EROFS
				printf("Output File: %s is read-only!\n", sys.output_file);
				break;

			case 36: //ENAMETOOLONG
				printf("Imput File: %s name too long!\n", sys.input_file);
				break;

			case 90: //EMSGSIZE
				printf("Key Buffer is out of acceptable range!\n");
				break;
		}
		perror("Error");              
	}	
	
	return 0;
}
