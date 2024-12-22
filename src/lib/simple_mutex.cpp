
#include <cstdint>
#include <cwctype>
#include <sched.h>

  
void * simple_mutex_sync_obj_; 
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



