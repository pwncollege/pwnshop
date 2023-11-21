#define _GNU_SOURCE
#include <sys/sendfile.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <stdbool.h>
#include <assert.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <fcntl.h>

int main(int argc, char **argv, char **envp)
{
  { % if challenge.print_greeting %}
  printf("###\n");
  printf("### Welcome to %s!\n", argv[0]);
  printf("###\n\n");
  {% endif %}

  setvbuf(stdin, NULL, _IONBF, 0);
  setvbuf(stdout, NULL, _IONBF, 1);

  {% include challenge.interaction_template %}
}
