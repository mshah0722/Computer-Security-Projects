#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode-64.h"

// rip at 0x3021fea8
// p &buf : $1 = (char (*)[156]) 0x3021fdf0
// p &len : $2 = (int *) 0x3021fe9c
// p &i : $3 = (int *) 0x3021fe98

#define TARGET "../targets/target4"

int main(void)
{
  char *args[3];
  char *env[1];

  args[0] = TARGET; args[1] = "hi there"; args[2] = NULL;
  env[0] = NULL;

  if (0 > execve(TARGET, args, env))
    fprintf(stderr, "execve failed.\n");

  return 0;
}
