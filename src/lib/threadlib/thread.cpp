#include "threadlib/thread.h"
#include <cstdint>
#include <cstdio>
#include <ucontext.h>
#include "macros.hpp"
#include "threadlib/cpu.h"
#include "threadlib/schedulerState.h"
#include "debug.hpp"


stack_pool pool;

uint64_t next_tid = 1; // initialize the first thread id

int total_threads = 0;
/**
 * Wrapper function that calls the actual thread function and handles return,
 * properly deallocate finished threads
 * @param func the function that the thread will call
 * @param arg the arguments of the function
 * @param wait the waitable object of the thread
 * @param isDead the shared boolean to store the thread liveness information
 * @param stackptr the thread's stack pointer
 * @param recycle point to the context to be deallocated
*/
void threadWrapperFunc(thread_startfunc_t func, 
    void *arg, 
    waitable * wait, 
    shared_bool *isDead, 
    char *stackptr,
    ucontext_t *recycle){
    cpu::self()->thread_handler();
    DEBUG_STMT(printf("run wrapper\n"));
    UNLOCK
    cpu::interrupt_enable();
    func(arg);
    DEBUG_STMT(printf("completed thread\n"));
    cpu::interrupt_disable();
    LOCK
    SchedulerState::scheduler.wakeAll(wait);
    UNLOCK
    cpu::self()->setDone(stackptr, wait, recycle);
    isDead->val = true;
    isDead->ownedByStack = false;
    if (!isDead->ownedByThread) delete isDead;
    SchedulerState::scheduler.runNextFromUser();
}

/**
 * Thread Constructor, allocate thread, throw exceptions if failed
*/
thread::thread(thread_startfunc_t func, void* arg) {
    DEBUG_STMT(printf("MAKE NEW THREAD\n"));
    cpu::interrupt_disable(); 
    this->isDead                = nullptr;
    this->wait                  = nullptr;
    ucontext_t *ucontext_ptr    = nullptr;
    void * stackptr             = pool.pop();
    if (stackptr == nullptr) throw;
    try {
        this->isDead = new shared_bool{true, true, false};
        this->wait   = new waitable();
        ucontext_ptr = new ucontext_t;
        
        getcontext(ucontext_ptr);
        ucontext_ptr->uc_stack.ss_sp = stackptr;
        ucontext_ptr->uc_stack.ss_size = PAGES_PER_STACK * PAGE_SIZE;
        ucontext_ptr->uc_link = nullptr;
        makecontext(ucontext_ptr, (void (*)())threadWrapperFunc, 6,
            func,
            arg,
            this->wait,
            isDead,
            stackptr,
            ucontext_ptr);
    
    } catch (std::bad_alloc) {
        if (!this->isDead)  delete this->isDead;
        if (!this->wait)    delete this->wait;
        if (!ucontext_ptr)  delete ucontext_ptr;
        if (!stackptr)      pool.push((char *)stackptr);
        cpu::interrupt_enable(); 
        throw;
    }

    LOCK
    try {
        tid_map[ucontext_ptr] = next_tid++;
        DEBUG_STMT(printf("!!!ADD NEW THREAD WITH STACK %lx\n", (intptr_t)ucontext_ptr->uc_stack.ss_sp));
        SchedulerState::scheduler.putInReady(ucontext_ptr);
        DEBUG_STMT(printf("!!!ADD NEW THREAD WITH STACK %lx\n", (intptr_t)ucontext_ptr->uc_stack.ss_sp));
    } catch (std::bad_alloc) {
        UNLOCK
        cpu::interrupt_enable();
        throw;
    }
    total_threads++;
    UNLOCK
    cpu::interrupt_enable();
}

/**
 * Thread Destructor, deallocate shared boolean isDead
*/
thread::~thread() {
    cpu::interrupt_disable();
    this->isDead->ownedByThread = false;
    if (!isDead->ownedByStack) delete isDead;
    cpu::interrupt_enable();
}

/**
 * thread join, add the thread which calls this function
 * to the running thread's waiting queue
*/
void thread::join() {
    cpu::interrupt_disable();
    LOCK
    if (!(isDead->val)) {
        SchedulerState::scheduler.waitSelfOn(this->wait);
    }
    UNLOCK
    cpu::interrupt_enable();
}

/**
 * thread yield, push self to the back of the ready queue,
 * run the next ready thread on the ready queue
*/
void thread::yield() {
    cpu::interrupt_disable();
    SchedulerState::scheduler.putSelfInReady();
    cpu::interrupt_enable();
}
