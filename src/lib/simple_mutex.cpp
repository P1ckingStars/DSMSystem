
#include "simple_mutex.hpp"
#include <cstdint>
#include <cwctype>
#include <sched.h>

  
void * simple_mutex_sync_obj_; 
static inline uint
xchgl(volatile uint *addr, uint newval)
{   
  uint result;
  asm volatile("lock; xchgl %0, %1" :
               "+m" (*addr), "=a" (result) :
               "1" (newval) :
               "cc");
  return result;
}
inline bool test_and_set(SimpleMutex * mu) {
    uint test = 1;
    return xchgl(mu, test);
}

void SimpleMutexSyncImpl::lock_impl(SimpleMutex * mu) {
    while (test_and_set(mu)) {
        sched_yield();
    }
}

void SimpleMutexSyncImpl::unlock_impl(SimpleMutex * mu) {
    *mu = 0;
}

void SimpleMutexSyncImpl::wait_impl(SimpleNotDefinedCondvar * cond, SimpleMutex * mu) {
}
void SimpleMutexSyncImpl::signal_impl(SimpleNotDefinedCondvar * cond) {
}






