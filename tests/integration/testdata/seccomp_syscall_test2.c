#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main() {
  if (chdir("/") < 0 && errno == ENXIO)
    exit(EXIT_SUCCESS);
  fprintf(stderr, "got errno=%m\n");
  exit(EXIT_FAILURE);
}
