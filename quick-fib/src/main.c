#include <stdio.h>

#include "quick_fib.h"

int main() {
  for (int i = -40; i < 40; i++) {
    printf("quick_fib(%d): %ld\n", i, quick_fib(i));
  }
  return 0;
}

