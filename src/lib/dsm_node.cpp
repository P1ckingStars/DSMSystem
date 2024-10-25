#include "dsm_node.hpp"
#include "debug.hpp"
#include "fault.hpp"
#include "rpc/client.h"
#include "rpc/rpc_error.h"
#include "simple_mutex.hpp"
#include "syncheader.hpp"
#include <assert.h>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <errno.h>
#include <fcntl.h>
#include <iostream>
#include <linux/userfaultfd.h>
#include <poll.h>
#include <pthread.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/ioctl.h>
#include <sys/ipc.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/shm.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/ucontext.h>
#include <thread>
#include <unistd.h>
#include <vector>

using namespace dsm;

#define RPC_HAND_SHAKE "hand_shake"
#define RPC_JOIN "join"
#define RPC_READ "read"
#define RPC_WRITE "write"

#define DSM_PROT_READ 0b1
#define DSM_PROT_WRITE 0b111
#define DSM_PROT_OWNED 0b101
#define DSM_PROT_INVALID 0

#define DSM_PROT_CHECK(INFO, PROT) (((INFO) & PROT) == PROT)
#define READABLE(pinfo) DSM_PROT_CHECK(pinfo, DSM_PROT_READ)
#define WRITABLE(pinfo) DSM_PROT_CHECK(pinfo, DSM_PROT_WRITE)
#define OWNERSHIP(pinfo) DSM_PROT_CHECK(pinfo, DSM_PROT_OWNED)

#define FLOOR(addr) ((addr) / PAGE_SIZE * PAGE_SIZE)

namespace dsm {

DSMNode *dsm_singleton;

}

inline void resolve_by_copy(int uffd, intptr_t dst, intptr_t src, int prot) {
  struct uffdio_copy copy;
  copy.dst = (long long)dst;
  copy.len = PAGE_SIZE;
  copy.mode = prot == DSM_PROT_WRITE ? 0 : UFFDIO_COPY_MODE_WP;
  copy.src = src;
  if (ioctl(uffd, UFFDIO_COPY, &copy) == -1) {
    perror("ioctl/copy");
    exit(1);
  }
  printf("resolved page fault");
}

char *dsm::dsm_init_master(NodeAddr self, size_t size) {
  int swap_fd = memfd_create(".swap", 0);
  ftruncate(swap_fd, size);
  char *mem_region =
      (char *)mmap(0, size, PROT_READ | PROT_WRITE, MAP_SHARED, swap_fd, 0);
  int proj_id = rand();
  key_t ipc_key = ftok("./ipc", proj_id);
  int shmid = shmget(ipc_key, PAGE_SIZE * 2, 0666 | IPC_CREAT);
  void *ipc_region = shmat(shmid, nullptr, 0);
  dsm_kernel_ipc_region::dsm_region_init((dsm_kernel_ipc_region *)ipc_region);
  DEBUG_STMT(printf("addr of mem_region: 0x%lx\n", ((intptr_t)mem_region)));
  int uffd = faultfd_init(mem_region, size);
  if (fork() == 0) {
    DSMNode *node;
    DEBUG_STMT(printf("create master\n"));
    DEBUG_STMT(printf("make new node\n"));
    node = new DSMNode(self, mem_region, size, true, swap_fd, ipc_region);
    DSMSync::create(node);
    DEBUG_STMT(printf("finish make new node\n"));
    page_fault_service(&uffd);
  } else {
    pthread_t t;
    DEBUG_STMT(printf("start page manage service\n"));
    pthread_create(&t, NULL, page_manage_service, ipc_region);
  }
  return mem_region;
}
char *dsm::dsm_init_node(NodeAddr self, NodeAddr dst, size_t size,
                         int node_id) {
  int swap_fd = memfd_create(".swap", 0);
  ftruncate(swap_fd, size);
  char *mem_region =
      (char *)mmap(0, size, PROT_READ | PROT_WRITE, MAP_SHARED, swap_fd, 0);
  int proj_id = rand();
  key_t ipc_key = ftok("./ipc", proj_id + node_id);
  int shmid = shmget(ipc_key, PAGE_SIZE * 2, 0666 | IPC_CREAT);
  void *ipc_region = shmat(shmid, nullptr, 0);
  dsm_kernel_ipc_region::dsm_region_init((dsm_kernel_ipc_region *)ipc_region);
  DEBUG_STMT(printf("addr of mem_region: 0x%lx\n", ((intptr_t)mem_region)));
  int uffd = faultfd_init(mem_region, size);
  if (fork() == 0) {
    DSMNode *node;
    DEBUG_STMT(printf("create process\n"));
    DEBUG_STMT(printf("make new node\n"));
    node = new DSMNode(self, mem_region, size, false, swap_fd, ipc_region);
    DSMSync::create(node);
    DEBUG_STMT(printf("finish make new node\n"));
    NodeAddr dst_addr;
    DEBUG_STMT(printf("try connect\n"));
    node->connect(dst);
    page_fault_service(&uffd);
  } else {
    pthread_t t;
    DEBUG_STMT(printf("start page manage service\n"));
    pthread_create(&t, NULL, page_manage_service, ipc_region);
  }
  return mem_region;
}

bool DSMNode::is_in_range(char *addr) {
  return (intptr_t)addr >= (intptr_t)this->base &&
         (intptr_t)addr <
             ((intptr_t)this->base) + PAGE_SIZE * this->page_info.size();
}

void DSMNode::request_hand_shake(NodeAddr my_addr, NodeAddr dst_addr) {
  DEBUG_STMT(
      printf("HANDSHAKE REQ TO %s:%d\n", dst_addr.ip.c_str(), dst_addr.port));
  rpc::client cli(dst_addr.ip, dst_addr.port);
  cli.call(RPC_HAND_SHAKE, m_addr);
}

void DSMNode::respond_hand_shake(NodeAddr src_addr) {
  DEBUG_STMT(printf("Received hand shake from %s:%d\n", src_addr.ip.c_str(),
                    src_addr.port));
  this->conn.push_back(src_addr);
}

vector<NodeAddr> DSMNode::request_join(NodeAddr dst_addr) {
  DEBUG_STMT(printf("JOIN REQ TO %s:%d\n", dst_addr.ip.c_str(), dst_addr.port));
  try {
    rpc::client cli(dst_addr.ip, dst_addr.port);
    return cli.call(RPC_JOIN).as<vector<NodeAddr>>();
  } catch (rpc::rpc_error err) {
    DEBUG_STMT(printf("%s\n", err.what()));
    return vector<NodeAddr>();
  }
}
vector<NodeAddr> DSMNode::respond_join() {
  DEBUG_STMT(printf("received join\n"));
  return this->conn;
}

page DSMNode::request_write(NodeAddr dst_addr, uint64_t pagenum) {
  DEBUG_STMT(
      printf("WRITE REQ TO %s:%d\n", dst_addr.ip.c_str(), dst_addr.port));
  rpc::client cli(dst_addr.ip, dst_addr.port);
  return cli.call(RPC_WRITE, pagenum).as<page>();
}

page DSMNode::response_write(uint64_t relative_page_id) {
  DEBUG_STMT(printf("recieved write req %lx\n", relative_page_id));
  page res;
  res.clear();
  LOCK(this->mu)
  if (this->page_info.size() > relative_page_id &&
      READABLE(this->page_info[relative_page_id])) {

#ifndef RELEASE_CONSISTANCY
    this->ipc_region->mprotect_req((void *)VPID2VPADDR(pagenum), PAGE_SIZE,
                                   PROT_NONE);
#endif
    if (OWNERSHIP(this->page_info[relative_page_id])) {
#ifdef RELEASE_CONSISTANCY
      this->page_info[relative_page_id] = DSM_PROT_READ;
      this->ipc_region->mprotect_req(relative_page_id_to_addr(relative_page_id),
                                     PAGE_SIZE, PROT_READ);
#else
      this->page_info[relative_page_id] = 0;
#endif
      this_thread::sleep_for(std::chrono::milliseconds(random() % 100));
      res.resize(PAGE_SIZE);
      this->ipc_region->page_copy_req(
          &res[0], relative_page_id_to_addr(relative_page_id));
      DEBUG_STMT(printf("setup result page\n"));
    }
  }
  UNLOCK(this->mu)
  return res;
}

page DSMNode::request_read(NodeAddr dst_addr, uint64_t pagenum) {
  DEBUG_STMT(printf("READ REQ TO %s:%d\n", dst_addr.ip.c_str(), dst_addr.port));
  rpc::client cli(dst_addr.ip, dst_addr.port);
  return cli.call(RPC_READ, pagenum).as<page>();
}

page DSMNode::response_read(uint64_t relative_page_id) {
  page res;
  res.clear();
  DEBUG_STMT(printf("recieved read req %lx\n", relative_page_id));
  LOCK(this->mu)
  if (this->page_info.size() > relative_page_id &&
      OWNERSHIP(this->page_info[relative_page_id])) {
    DEBUG_STMT(printf("master respond %lx\n",
                      (intptr_t)relative_page_id_to_addr(relative_page_id)));
#ifndef RELEASE_CONSISTANCY
    this->page_info[relative_page_id] = DSM_PROT_OWNED;
#endif
    res.resize(PAGE_SIZE);
    this->ipc_region->page_copy_req(&res[0], relative_page_id_to_addr(relative_page_id));
    DEBUG_STMT(printf("master respond done\n"));
  }
  UNLOCK(this->mu)
  return res;
}

void DSMNode::connect(NodeAddr dst_addr) {
  this->conn = request_join(dst_addr);
  this->conn.push_back(dst_addr);
  DEBUG_STMT(printf("connect %s:%d\n", dst_addr.ip.c_str(), dst_addr.port));
  struct thread_arg {
    DSMNode *self;
    int idx;
  };
  pthread_t *threads =
      (pthread_t *)malloc(sizeof(pthread_t) * this->conn.size());
  thread_arg *args = (thread_arg *)malloc(this->conn.size());
  for (int i = 0; i < this->conn.size(); i++) {
    args[i].self = this;
    args[i].idx = i;
    pthread_create(
        &threads[i], NULL,
        [](void *input) -> void * {
          thread_arg *arg = (thread_arg *)input;
          DSMNode *self = (DSMNode *)arg->self;
          self->request_hand_shake(self->m_addr, self->conn[arg->idx]);
          return NULL;
        },
        &args[i]);
  }
  for (int i = 0; i < this->conn.size(); i++) {
    pthread_join(threads[i], NULL);
  }
  free(args);
  free(threads);
}

struct thread_arg_content {
  DSMNode *self;
  page data;
  pthread_mutex_t mu;
  pthread_cond_t cond;
  int count;
};
struct thread_arg {
  thread_arg_content *content;
  int idx;
  int relative_page_id;
  int prot;
};

bool DSMNode::grant_prot(page_id_t relative_page_id, int prot) {
  DEBUG_STMT(printf("requesting protection \n"));
  page res;
  pthread_t *threads =
      (pthread_t *)malloc(sizeof(pthread_t) * this->conn.size());
  thread_arg_content *arg_content = new thread_arg_content();
  arg_content->self = this;
  arg_content->data.clear();
  arg_content->count = this->conn.size();
  thread_arg *args = new thread_arg[this->conn.size()];

  pthread_mutex_init(&arg_content->mu, NULL);
  pthread_cond_init(&arg_content->cond, NULL);
  DEBUG_STMT(printf("sending rpc..."));
  for (int i = 0; i < this->conn.size(); i++) {
    args[i].content = arg_content;
    args[i].idx = i;
    args[i].relative_page_id = relative_page_id;
    args[i].prot = prot;
    DEBUG_STMT(printf("relative_page_id %x\n", args[i].relative_page_id));
    pthread_create(
        &threads[i], NULL,
        [](void *input) -> void * {
          thread_arg *arg = (thread_arg *)input;
          DSMNode *self = arg->content->self;
          auto res = arg->prot == DSM_PROT_READ
                         ? self->request_read(self->conn[arg->idx],
                                              arg->relative_page_id)
                         : self->request_write(self->conn[arg->idx],
                                               arg->relative_page_id);
          LOCK(arg->content->mu)
          DEBUG_STMT(printf("received page with size %ld\n", res.size()));
          if (res.size() == PAGE_SIZE) {
            arg->content->data = res;
          }
          arg->content->count--;
          // SIGNAL(arg->content->cond)
          UNLOCK(arg->content->mu)
          delete arg;
          return NULL;
        },
        &args[i]);
  }
#ifdef RELEASE_CONSISTANCY
  // while (arg_content->data.size() != PAGE_SIZE && arg_content->count) {
  //     WAIT(arg_content->cond, arg_content->mu)
  // }
  for (int i = 0; i < this->conn.size(); i++) {
    pthread_join(threads[i], nullptr);
  }
#else
  for (int i = 0; i < this->conn.size(); i++) {
    pthread_join(threads[i]);
  }
#endif
  bool succeed = false;
  if (arg_content->data.size() == PAGE_SIZE) {
    resolve_by_copy(uffd, (intptr_t)relative_page_id_to_addr(relative_page_id),
                    arg_content->data[0], prot);
    succeed = true;
  }
  DEBUG_STMT(printf("got rpc response %d\n", succeed));
  delete threads;
  delete arg_content;
  delete[] args;
  return succeed;
}

bool DSMNode::grant_write(char *addr) {
  LOCK(this->mu)
  UNLOCK(this->mu)
  page_id_t relative_page_id = relative_page_id_from_addr(addr);
  bool res = this->grant_prot(relative_page_id, DSM_PROT_WRITE);
  if (res) {
    LOCK(this->mu)
    this->page_info[relative_page_id] = DSM_PROT_WRITE;
    this->ipc_region->mprotect_req((void *)FLOOR((intptr_t)addr), PAGE_SIZE,
                                   PROT_READ | PROT_WRITE);
    UNLOCK(this->mu)
  }
  return res;
}

bool DSMNode::grant_read(char *addr) {
  LOCK(this->mu)
  UNLOCK(this->mu)
  page_id_t relative_page_id = relative_page_id_from_addr(addr);
  bool res = this->grant_prot(relative_page_id, DSM_PROT_READ);
  if (res) {
    LOCK(this->mu)
    this->page_info[relative_page_id] = DSM_PROT_READ;
    this->ipc_region->mprotect_req((void *)FLOOR((intptr_t)addr), PAGE_SIZE,
                                   PROT_READ);
    UNLOCK(this->mu)
  }
  return res;
}

void DSMNode::sync() {
  for (int i = 0; i < this->page_info.size(); i++) {
    if (OWNERSHIP(this->page_info[i]))
      continue;
    this->ipc_region->mprotect_req(relative_page_id_to_addr(i), PAGE_SIZE,
                                   PROT_NONE);
  }
}

DSMNode::DSMNode(NodeAddr m_addr, void *_base, size_t _len, bool is_master,
                 int swapfd, void *ipc_region) {
  this->ipc_region = (dsm_kernel_ipc_region *)ipc_region;
  this->swap_file_fd = swapfd;
  DEBUG_STMT(printf("is master %d\n", is_master));
  int pages = VPADDR2VPID(_len);
  page_info.resize(pages);
  for (int i = 0; i < pages; i++) {
    this->page_info[i] = is_master ? DSM_PROT_WRITE : DSM_PROT_INVALID;
  }
  this->base = (char *)_base;
  DEBUG_STMT(printf("check mmap equal %lx\n", (intptr_t)this->base));
  ASSERT_PERROR(this->base);
  if (!is_master) {
    this->ipc_region->mprotect_req(_base, _len, PROT_NONE);
  }

  DEBUG_STMT(printf("setup mem\n"));
  this->m_addr = m_addr;
  if (pthread_mutex_init(&this->mu, NULL)) {
    exit(-1);
  }
  serv = new rpc::server(m_addr.port);
  serv->bind(RPC_HAND_SHAKE, [this](NodeAddr src_addr) -> void {
    return this->respond_hand_shake(src_addr);
  });
  serv->bind(RPC_JOIN,
             [this]() -> vector<NodeAddr> { return this->respond_join(); });
  serv->bind(RPC_WRITE, [this](uint64_t pagenum) -> page {
    return this->response_write(pagenum);
  });
  serv->bind(RPC_READ, [this](uint64_t pagenum) -> page {
    return this->response_read(pagenum);
  });
  dsm_singleton = this;
  pthread_create(
      &this->tid, NULL,
      [](void *input) -> void * {
        rpc::server *serv = (rpc::server *)input;
        serv->run();
        return nullptr;
      },
      serv);
  DEBUG_STMT(printf("run server\n"));
}

#define YIELD_LOCK(mu)                                                         \
  {                                                                            \
    UNLOCK(mu);                                                                \
    sched_yield();                                                             \
    LOCK(mu);                                                                  \
  }

void dsm_kernel_ipc_region::run_ipc_server() {
  while (1) {
    while (this->event_id == IPC_NONE) {
      sched_yield();
    }
    DEBUG_STMT(printf("request received\n"));
    switch (this->event_id) {
    case IPC_PAGE_COPY:
      memcpy(this->page, this->event.page_copy.src, PAGE_SIZE);
      this->event_id = IPC_COMPLETE;
      DEBUG_STMT(printf("done copy request\n"));
      break;
    case IPC_MPROTECT:
      DEBUG_STMT(printf("try mprotect request %lx, %lx, %d\n",
                        (intptr_t)this->event.mprotect.addr,
                        this->event.mprotect.len, this->event.mprotect.prot));
      mprotect(this->event.mprotect.addr, this->event.mprotect.len,
               this->event.mprotect.prot);
      DEBUG_STMT(printf("done mprotect request\n"));
      this->event_id = IPC_COMPLETE;
      DEBUG_STMT(printf("done mprotect request\n"));
      break;
    default:
      break;
    }
    DEBUG_STMT(printf("request finished\n"));
  }
}

#define SPIN_LOCK(mu)                                                          \
  {                                                                            \
    while (test_and_set(&mu))                                                  \
      ;                                                                        \
  }
#define SPIN_UNLOCK(mu)                                                        \
  { mu = 0; }

void dsm_kernel_ipc_region::page_copy_req(char *dst, const char *src) {
  SPIN_LOCK(this->mu);
  DEBUG_STMT(printf("try send copy request\n"));
  while (this->event_id != IPC_NONE) {
    sched_yield();
  }
  this->event.page_copy.src = src;
  this->event_id = IPC_PAGE_COPY;
  SPIN_UNLOCK(this->mu);
  DEBUG_STMT(printf("request sent\n"));
  while (this->event_id != IPC_COMPLETE) {
    sched_yield();
  }
  memcpy(dst, this->page, PAGE_SIZE);
  this->event_id = IPC_NONE;
}

void dsm_kernel_ipc_region::mprotect_req(void *addr, size_t len, int prot) {
  SPIN_LOCK(this->mu);
  DEBUG_STMT(printf("try send mprotect request\n"));
  while (this->event_id != IPC_NONE) {
    sched_yield();
  }
  this->event.mprotect.addr = addr;
  this->event.mprotect.len = len;
  this->event.mprotect.prot = prot;
  this->event_id = IPC_MPROTECT;
  SPIN_UNLOCK(this->mu);
  DEBUG_STMT(printf("request sent\n"));
  while (this->event_id != IPC_COMPLETE) {
    sched_yield();
  }
  DEBUG_STMT(printf("request done\n"));
  this->event_id = IPC_NONE;
}
