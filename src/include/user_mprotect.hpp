#ifndef USER_MPROTECT_HPP
#define USER_MPROTECT_HPP

#include <cstddef>
#include <cstdint>
#include <pthread.h>
#include <sys/types.h>


void user_mprotect_init();
void user_mprotect_req(pid_t pid, void *addr, size_t size, int prot);
void user_mprotect_respond();
void user_mprotect(pid_t pid, void *addr, size_t size, int prot);

#endif
