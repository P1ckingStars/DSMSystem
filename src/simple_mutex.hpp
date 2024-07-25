#ifndef SIMPLE_MUTEX_HPP
#define SIMPLE_MUTEX_HPP

#include "sync_interface.hpp"

typedef uint SimpleMutex;

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

