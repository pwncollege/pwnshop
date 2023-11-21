# Usage Example

## Basic

```sh
python -m pwnshop --challenge BabyShellBase
```

```c
#include <sys/mman.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <assert.h>
#include <unistd.h>
#include <stdio.h>

int main(int argc, char **argv, char **envp)
{
  assert(argc > 0);

  printf("###\n");
  printf("### Welcome to %s!\n", argv[0]);
  printf("###\n");
  printf("\n");
  printf("This challenge reads in some bytes, modifies them (depending on the specific\n");
  printf("challenge configuration, and executes them as code! This is a common exploitation\n");
  printf("scenario, called \"code injection\". Through this series of challenges, you will\n");
  printf("practice your shellcode writing skills under various constraints!\n");
  printf("\n");



  for (int i = 3; i < 10000; i++) close(i);
  for (char **a = argv; *a != NULL; a++) memset(*a, 0, strlen(*a));
  for (char **a = envp; *a != NULL; a++) memset(*a, 0, strlen(*a));
}
```

## Walkthrough

```sh
python -m pwnshop --challenge BabyShellBase --walkthrough
```

```c
#include <sys/mman.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <assert.h>
#include <unistd.h>
#include <stdio.h>

int main(int argc, char **argv, char **envp)
{
  assert(argc > 0);

  printf("###\n");
  printf("### Welcome to %s!\n", argv[0]);
  printf("###\n");
  printf("\n");
  printf("This challenge reads in some bytes, modifies them (depending on the specific\n");
  printf("challenge configuration, and executes them as code! This is a common exploitation\n");
  printf("scenario, called \"code injection\". Through this series of challenges, you will\n");
  printf("practice your shellcode writing skills under various constraints!\n");
  printf("\n");


  printf("To ensure that you are shellcoding, rather than doing other tricks, this\n");
  printf("will sanitize all environment variables and arguments and close all file\n");
  printf("descriptors > 2,\n");
  printf("\n");


  for (int i = 3; i < 10000; i++) close(i);
  for (char **a = argv; *a != NULL; a++) memset(*a, 0, strlen(*a));
  for (char **a = envp; *a != NULL; a++) memset(*a, 0, strlen(*a));
}
```