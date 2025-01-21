
#include "user_mprotect.hpp"
#include "debug.hpp"
#include <csignal>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <pthread.h>
#include <sched.h>
#include <strings.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/uio.h>
#include <sys/user.h>
#include <sys/wait.h>

class {
  pthread_mutex_t mu_;
  pid_t pid_;
  void *addr_;
  size_t size_;
  int prot_;
  uint8_t status_;
#define REQ_INCOMPLETE 0
#define REQ_COMPLETE 1
public:
  void init() { pthread_mutex_init(&mu_, NULL); }
  void produce(pid_t pid, void *addr, size_t size, int prot) {
    pthread_mutex_lock(&mu_);
    this->pid_ = pid;
    this->addr_ = addr;
    this->size_ = size;
    this->prot_ = prot;
    this->status_ = REQ_INCOMPLETE;
  }
  void consume(pid_t *pid, void **addr, size_t *size, int *prot) {
    *pid = this->pid_;
    *addr = this->addr_;
    *size = this->size_;
    *prot = this->prot_;
  }
  void compelete() { this->status_ = REQ_COMPLETE; }
  void wait_to_compelete() {
    while (this->status_ == REQ_INCOMPLETE)
      ;
    pthread_mutex_unlock(&mu_);
  }
} mprotect_req;

void injection();
void injection2() {
  printf("inject\n");
  int *x = 0;
  int y = *x;
}

void user_mprotect_init() { mprotect_req.init(); }

void user_mprotect_req(pid_t pid, void *addr, size_t size, int prot) {
  DEBUG_STMT(printf("try user mprotect\n"));
  mprotect_req.produce(pid, addr, size, prot);
  DEBUG_STMT(printf("rsps sent\n"));
  kill(pid, SIGUSR2);
  DEBUG_STMT(printf("wait to complete\n"));
  mprotect_req.wait_to_compelete();
}

void user_mprotect_respond() {
  pid_t pid;
  void *addr;
  size_t size;
  int prot;
  mprotect_req.consume(&pid, &addr, &size, &prot);
  user_mprotect(pid, addr, size, prot);
  mprotect_req.compelete();
  DEBUG_STMT(printf("complete\n"));
}

void user_mprotect(pid_t pid, void *addr, size_t size, int prot) {
  DEBUG_STMT(printf("user mprotect BEGIN at ADDR: %lx, PROT: %d\n",
                    (intptr_t)addr, prot));
  user_regs_struct regs;
  user_regs_struct saved_regs;
  user_fpregs_struct saved_fp_regs;
  iovec saved_pr_state;
  ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &saved_pr_state);
  ptrace(PTRACE_GETREGS, pid, 0, &saved_regs);
  ptrace(PTRACE_GETFPREGS, pid, 0, &saved_fp_regs);
  printf("iovec len %zu\n", saved_pr_state.iov_len);
  bzero(&regs, sizeof(regs));
  regs.rax = 10;
  regs.rdi = (intptr_t)addr;
  regs.rsi = size;
  regs.rdx = prot;
  regs.rip = (intptr_t)injection;
  int err = ptrace(PTRACE_SETREGS, pid, NULL, &regs);
  if (err != 0) {
    perror("ptrace");
  }
  ptrace(PTRACE_CONT, pid, NULL, NULL);
  DEBUG_STMT(printf("continue\n"));
  wait(NULL);
  siginfo_t sig;
  ptrace(PTRACE_GETSIGINFO, pid, NULL, &sig);
  DEBUG_STMT(printf("user mprotect recv sig: %d\n", sig.si_signo));
  // reg_err = ptrace(PTRACE_PEEKDATA, child, reg_err, &sig);
  ptrace(PTRACE_SETREGSET, pid, 1, &saved_pr_state);
  ptrace(PTRACE_SETREGS, pid, 0, &saved_regs);
  ptrace(PTRACE_SETFPREGS, pid, 0, &saved_fp_regs);
  DEBUG_STMT(
      printf("user mprotect FINISHED at ADDR: %lx, PROT: %d, PROT read: %d\n",
             (intptr_t)addr, prot, PROT_READ));
}
