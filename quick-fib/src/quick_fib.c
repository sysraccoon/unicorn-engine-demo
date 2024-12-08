#include <stdlib.h>
#include <math.h>

#include "quick_fib.h"

long quick_fib(int n) {
  double fib_base = sqrt(5);
  double phi = (1.0 + fib_base) / 2.0;
  double result = rintl(pow(phi, abs(n)) / fib_base);
  return pow(copysign(1.0, n), abs(n)+1) * result;
}
