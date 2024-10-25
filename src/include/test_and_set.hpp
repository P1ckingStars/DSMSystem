#ifndef TEST_AND_SET_HPP
#define TEST_AND_SET_HPP

inline int
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

#endif
