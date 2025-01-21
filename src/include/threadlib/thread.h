/*
 * thread.h -- interface to the thread library
 *
 * This file should be included by the thread library and by application
 * programs that use the thread library.
 * 
 * You may add new variables and functions to this class.
 *
 * Do not modify any of the given function declarations.
 */
#include <sys/ucontext.h>
#include <ucontext.h>
#include "waitable.h"

#pragma once


static constexpr unsigned int STACK_SIZE=1024; //262144; // size of each thread's stack in bytes

using thread_startfunc_t = void (*)(void*);

/**
 * a class of shared boolean to store the information that if its owner is alive
*/
class shared_bool {
public:
    bool ownedByStack;
    bool ownedByThread;
    bool val;
};

class thread {
public:
    uint64_t tid; // a unique thread id for each thread
    shared_bool *isDead; // store the information that if this thread is alive
    waitable *wait; // a waitable object that stores other threads
                    // that wait for this thread to exit
    thread(thread_startfunc_t func, void* arg); // create a new thread
    ~thread();

    void join();                                // wait for this thread to finish

    static void yield();                        // yield the CPU
    //static void swapToMaster();

    /*
     * Disable the copy constructor and copy assignment operator.
     */
    thread(const thread&) = delete;
    thread& operator=(const thread&) = delete;

    /*
     * Move constructor and move assignment operator.  Implementing these is
     * optional in Project 2.
     */
    thread(thread&&);
    thread& operator=(thread&&);
};
