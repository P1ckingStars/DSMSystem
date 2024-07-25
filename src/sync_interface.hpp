#ifndef SYNC_INTERFACE_HPP
#define SYNC_INTERFACE_HPP

#include "debug.hpp"
#include "dsm_node.hpp"
#include "singleton.hpp"
#include <cstdio>


template <class Mutex, class Condvar>
class SyncImpl {
public:
    SyncImpl() {}
    virtual void lock_impl(Mutex * mu)                  = 0;
    virtual void unlock_impl(Mutex * mu)                = 0;
    virtual void wait_impl(Condvar * cond, Mutex * mu)  = 0;
    virtual void signal_impl(Condvar * cond)            = 0;
};
template <class Mutex, class Condvar, class Sync, void ** obj_>
class SyncManager : public Singleton<SyncManager<Mutex, Condvar, Sync, obj_>, obj_> {
    dsm::DSMNode * node_;
    SyncImpl<Mutex, Condvar> * impl_;
public:
    explicit SyncManager(dsm::DSMNode *node) : node_(node) {
        impl_ = new Sync();
    }
    void lock(Mutex *mu) { 
        DEBUG_STMT(printf("impl_ addr: %lx\n", impl_));
        impl_->lock_impl(mu); 
        DEBUG_STMT(printf("node addr: %lx\n", node_));
        this->node_->sync();
    }
    void unlock(Mutex *mu) { impl_->unlock_impl(mu); }
    void wait(Condvar *cond, Mutex *mu) { 
        impl_->wait_impl(cond, mu); 
        this->node_->sync();
    }
    void signal(Condvar *cond) { impl_->signal_impl(cond); }
};

#endif








