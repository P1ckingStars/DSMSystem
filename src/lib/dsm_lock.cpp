
#include <cstdint>
#include <cwctype>
#include <sched.h>

#include "dsm_lock.hpp"

using namespace dsm;
  
static inline int
xchgl(volatile int *addr, int newval)
{   
  int result;
  asm volatile("lock; xchgl %0, %1" :
               "+m" (*addr), "=a" (result) :
               "1" (newval) :
               "cc");
  return result;
}

inline bool test_and_set(int * mu) {
    int test = 1;
    return xchgl(mu, test);
}

void dsm_mutex_lock(dsm_mutex * mu) {
    while (test_and_set(mu));
}

void dsm_mutex_unlock(dsm_mutex * mu) {
    *mu = 0;
}

