#include <stdio.h>
#include <stdlib.h>
#include <syscall.h>

int main (int argc, char **argv)
{
  if (argc != 5) {
    printf("Usage: additional <int a> <int b> <int c> <int d>\n");
    return EXIT_FAILURE;
  }
    int a = atoi(argv[1]);
    int b = atoi(argv[2]);
    int c = atoi(argv[3]);
    int d = atoi(argv[4]);

    printf("%d %d\n",fibonacci(a), max_of_four_int(a, b, c, d));

    return EXIT_SUCCESS;
}
