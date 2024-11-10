#ifndef SIMPLE_MUTEX_HPP
#define SIMPLE_MUTEX_HPP

#include "sync_interface.hpp"

typedef uint SimpleMutex;
inline uint
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
class SimpleNotDefinedCondvar {
    char x;
};

extern void * simple_mutex_sync_obj_; 

class SimpleMutexSyncImpl: public SyncImpl<SimpleMutex, SimpleNotDefinedCondvar> {
    void lock_impl(SimpleMutex * mu)                                    override;
    void unlock_impl(SimpleMutex * mu)                                  override;
    void wait_impl(SimpleNotDefinedCondvar* cond, SimpleMutex * mu)     override;
    void signal_impl(SimpleNotDefinedCondvar * cond)                    override;
};


typedef SyncManager<SimpleMutex, SimpleNotDefinedCondvar, SimpleMutexSyncImpl, &simple_mutex_sync_obj_> DSMSync;

#endif

