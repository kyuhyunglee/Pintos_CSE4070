#include <stdio.h>
#include <syscall.h>

int
main (int argc, char **argv)
{
  int i;

  // 왠진 모르겠지만 원래 코드가 argv[0]부터 출력해서 이를 바꿈
  for (i = 1; i < argc; i++)
    printf ("%s ", argv[i]);
  printf ("\n");

  return EXIT_SUCCESS;
}
