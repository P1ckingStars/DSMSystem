#include "threadlib/mutex.h"
#include "threadlib/cpu.h"
#include <sys/ucontext.h>
#include <ucontext.h>
#include <stdexcept>
#include "threadlib/schedulerState.h"

#define MU "Mutex.cpp"

mutex::mutex(){}

mutex::~mutex(){}

/**
 * @return true if the lock is owned by a thread, or false otherwise
*/
bool mutex::status(){
    return isLocked;
}

/**
 * lock without disable interrupt, called by lock()
 * if lock is occupied, call waitSelfOn which calls switch context,
 * push self on the waiting queue,
 * and run the next thread on the ready queue,
 * or switch to main context if ready queue is empty 
*/
void mutex::privileged_lock(){
    if (isLocked == INUSE){
        SchedulerState::scheduler.waitSelfOn(this);
    }
    isLocked = INUSE;
    // assign lock's owner thread id
    owner_id = tid_map[cpu::self()->currContext];
}

/**
 * throw error if try to unlock when the lock is owned by other thread,
 * otherwise assign the lock to next thread that waits on the lock.
*/
void mutex::privileged_unlock(){
    if (owner_id != tid_map[cpu::self()->currContext]){
        throw std::runtime_error("can't unlock other's lock");
    }
    owner_id = 0;
    isLocked = FREE;
    if (!this->empty()){
        SchedulerState::scheduler.wakeOne(this);
        isLocked = INUSE;
    }
}

/**
 * disable interrupt and call privileged lock
*/
void mutex::lock(){
    cpu::interrupt_disable();
    LOCK
    privileged_lock();
    UNLOCK
    cpu::interrupt_enable();
}

/**
 * disable interrupt and call privileged lock, catch error if try to unlock unproperly
*/
void mutex::unlock(){
    cpu::interrupt_disable();
    LOCK
    try{
        privileged_unlock();
    }
    catch (std::exception){
        UNLOCK
        cpu::interrupt_enable();
        throw;
    }
    UNLOCK
    cpu::interrupt_enable();
}
