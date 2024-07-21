#include "dsm_node.hpp"
#include "rpc/client.h"
#include "rpc/rpc_error.h"
#include "syncheader.hpp"
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <iostream>
#include <pthread.h>
#include "debug.hpp"
#include <strings.h>
#include <sys/mman.h>
#include <sys/ucontext.h>
#include <unistd.h>
#include <vector>
#include <sys/mman.h>
#include <signal.h>

using namespace dsm;

#define RPC_HAND_SHAKE      "hand_shake"
#define RPC_JOIN            "join"
#define RPC_READ            "read"
#define RPC_WRITE           "write"

#define DSM_PROT_READ       0b1
#define DSM_PROT_WRITE      0b111
#define DSM_PROT_OWNED      0b101
#define DSM_PROT_INVALID    0

#define DSM_PROT_CHECK(INFO, PROT) (((INFO) & PROT) == PROT)
#define READABLE(pinfo)     DSM_PROT_CHECK(pinfo, DSM_PROT_READ)
#define WRITABLE(pinfo)     DSM_PROT_CHECK(pinfo, DSM_PROT_WRITE)
#define OWNERSHIP(pinfo)    DSM_PROT_CHECK(pinfo, DSM_PROT_OWNED)

#define FLOOR(addr) ((addr) / PAGE_SIZE * PAGE_SIZE)

static dsm_node * dsm_singleton;

static void handler(int sig, siginfo_t *si, void *unused) {
    ucontext_t * ctx = (ucontext_t *)unused;
    bool is_write = (ctx->uc_mcontext.gregs[REG_ERR] & 2);
    //DEBUG_STMT(printf("Got SIGSEGV at address: 0x%lx\n", (long)si->si_addr));
    if (is_write) {
        dsm_singleton->grant_write((char *)si->si_addr);
    } else {
        dsm_singleton->grant_read((char *)si->si_addr);
    }
}

void dsm::dsm_init() {
    struct sigaction sa;
    sa.sa_flags = SA_SIGINFO;
    sigemptyset(&sa.sa_mask);
    sa.sa_sigaction = handler;
    if (sigaction(SIGSEGV, &sa, NULL) == -1) {
        //DEBUG_STMT(printf("can't customize SEGV handler\n"));
        exit(-1);
    }
}

char * dsm::dsm_init_master(node_addr self, size_t size) {
    dsm_init();
    int swap_fd = memfd_create(".swap", 0);
    ftruncate(swap_fd, size);
    char * mem_region = (char *)mmap(0, size, PROT_READ | PROT_WRITE, MAP_SHARED, swap_fd, 0);
    //DEBUG_STMT(printf("addr of mem_region: 0x%lx\n", ((intptr_t)mem_region)));
    dsm_node * node;
    //DEBUG_STMT(printf("create master\n"));
    //DEBUG_STMT(printf("make new node\n"));
    node = new dsm_node(self, mem_region, size, true, swap_fd);
    //DEBUG_STMT(printf("finish make new node\n"));
    return mem_region;
}
char * dsm::dsm_init_node(node_addr self, node_addr dst, size_t size) {
    dsm_init();
    int swap_fd = memfd_create(".swap", 0);
    ftruncate(swap_fd, size);
    char * mem_region = (char *)mmap(0, size, PROT_READ | PROT_WRITE, MAP_SHARED, swap_fd, 0);
    //DEBUG_STMT(printf("addr of mem_region: 0x%lx\n", ((intptr_t)mem_region)));
    dsm_node * node;
    //DEBUG_STMT(printf("create process\n"));
    //DEBUG_STMT(printf("make new node\n"));
    node = new dsm_node(self, mem_region, size, false, swap_fd);
    //DEBUG_STMT(printf("finish make new node\n"));
    node_addr dst_addr;
    //DEBUG_STMT(printf("try connect\n"));
    node->connect(dst);
    return mem_region;
}

void dsm_node::request_hand_shake(node_addr my_addr, node_addr dst_addr) {
    //DEBUG_STMT(printf("HANDSHAKE REQ TO %s:%d\n", dst_addr.ip.c_str(), dst_addr.port));
    rpc::client cli(dst_addr.ip, dst_addr.port);
    cli.call(RPC_HAND_SHAKE, m_addr);
}

void dsm_node::respond_hand_shake(node_addr src_addr) {
    //DEBUG_STMT(printf("Received hand shake from %s:%d\n", src_addr.ip.c_str(), src_addr.port));
    this->conn.push_back(src_addr);
}

vector<node_addr> dsm_node::request_join(node_addr dst_addr) {
    //DEBUG_STMT(printf("JOIN REQ TO %s:%d\n", dst_addr.ip.c_str(), dst_addr.port));
    try {
        rpc::client cli(dst_addr.ip, dst_addr.port);
        return cli.call(RPC_JOIN).as<vector<node_addr>>();
    } catch (rpc::rpc_error err) {
        //DEBUG_STMT(printf("%s\n", err.what()));
        return vector<node_addr>();
    }
}
vector<node_addr> dsm_node::respond_join() {
    //DEBUG_STMT(printf("received join\n"));
    return this->conn;
}

page dsm_node::request_write(node_addr dst_addr, uint64_t pagenum) {
    //DEBUG_STMT(printf("WRITE REQ TO %s:%d\n", dst_addr.ip.c_str(), dst_addr.port));
    rpc::client cli(dst_addr.ip, dst_addr.port);
    return cli.call(RPC_WRITE, pagenum).as<page>();
    
}

page dsm_node::response_write(uint64_t relative_page_id) {
    //DEBUG_STMT(printf("recieved write req %lx\n", relative_page_id));
    page res;
    res.clear();
    LOCK(this->mu)
    if (this->page_info.size() > relative_page_id 
        && READABLE(this->page_info[relative_page_id])) {
        if (OWNERSHIP(this->page_info[relative_page_id])) {
            res.resize(PAGE_SIZE);
            memcpy(&res[0], relative_page_id_to_addr(relative_page_id), PAGE_SIZE);
            //DEBUG_STMT(printf("setup result page\n"));
        }
#ifdef RELEASE_CONSISTANCY
        this->page_info[relative_page_id] = DSM_PROT_READ;
        mprotect(relative_page_id_to_addr(relative_page_id), PAGE_SIZE, PROT_READ);
#else 
        this->page_info[relative_page_id] = 0;
        mprotect((void *)VPID2VPADDR(pagenum), PAGE_SIZE, PROT_NONE);
#endif
    }
    UNLOCK(this->mu)
    return res;   
}

page dsm_node::request_read(node_addr dst_addr, uint64_t pagenum) {
    //DEBUG_STMT(printf("READ REQ TO %s:%d\n", dst_addr.ip.c_str(), dst_addr.port));
    rpc::client cli(dst_addr.ip, dst_addr.port);
    return cli.call(RPC_READ, pagenum).as<page>();
}

page dsm_node::response_read(uint64_t relative_page_id) {
    page res;
    res.clear();
    //DEBUG_STMT(printf("recieved read req %lx\n", relative_page_id));
    LOCK(this->mu)
    if (this->page_info.size() > relative_page_id
        && OWNERSHIP(this->page_info[relative_page_id])) {
        //DEBUG_STMT(printf("master respond\n"));
        res.resize(PAGE_SIZE);
        memcpy(&res[0], relative_page_id_to_addr(relative_page_id), PAGE_SIZE);
#ifndef RELEASE_CONSISTANCY
        this->page_info[relative_page_id] = DSM_PROT_OWNED;
#endif
    }
    UNLOCK(this->mu)
    return res;
}


void dsm_node::connect(node_addr dst_addr) {
    this->conn = request_join(dst_addr);
    this->conn.push_back(dst_addr);
    //DEBUG_STMT(printf("connect %s:%d\n", dst_addr.ip.c_str(), dst_addr.port));
    struct thread_arg {
        dsm_node * self;
        int idx;
    };
    pthread_t * threads = (pthread_t *)malloc(sizeof(pthread_t) * this->conn.size());
    thread_arg * args = (thread_arg *)malloc(this->conn.size());
    for (int i = 0; i < this->conn.size(); i++) {
        args[i].self = this;
        args[i].idx = i;
        pthread_create(&threads[i], NULL, [](void * input) -> void * {
            thread_arg * arg = (thread_arg *)input;
            dsm_node * self = (dsm_node *)arg->self;
            self->request_hand_shake(self->m_addr, self->conn[arg->idx]);
            return NULL;
        }, &args[i]);
    }
    for (int i = 0; i < this->conn.size(); i++) {
        pthread_join(threads[i], NULL);
    }
    free(args);
    free(threads);
    
}

struct thread_arg_content {
    dsm_node *          self;
    page                data;
    pthread_mutex_t     mu;
    pthread_cond_t      cond;
    int                 count;
};
struct thread_arg {
    thread_arg_content *    content;
    int                     idx;
    int                     relative_page_id;
    int                     prot;
};


bool dsm_node::grant_prot(page_id_t relative_page_id, int prot) {
    //DEBUG_STMT(printf("requesting protection \n"));
    page res;
    pthread_t * threads                 = (pthread_t *)malloc(sizeof(pthread_t) * this->conn.size());
    thread_arg_content * arg_content    = new thread_arg_content();
    arg_content->self                   = this;
    arg_content->data.clear();
    arg_content->count                  = this->conn.size();
    thread_arg * args                   = new thread_arg[this->conn.size()];

    pthread_mutex_init(&arg_content->mu, NULL);
    pthread_cond_init(&arg_content->cond, NULL);
    //DEBUG_STMT(printf("sending rpc..."));
    for (int i = 0; i < this->conn.size(); i++) {
        args[i].content                 = arg_content;
        args[i].idx                     = i;
        args[i].relative_page_id        = relative_page_id;
        args[i].prot                    = prot;
        //DEBUG_STMT(printf("relative_page_id %x\n", args[i].relative_page_id));
        pthread_create(&threads[i], NULL, [](void * input) -> void * {
            thread_arg * arg            = (thread_arg *)input;
            dsm_node * self             = arg->content->self;
            auto res                    = arg->prot == DSM_PROT_READ ?
                self->request_read(self->conn[arg->idx], arg->relative_page_id) :
                self->request_write(self->conn[arg->idx], arg->relative_page_id);
            LOCK(arg->content->mu)
            //DEBUG_STMT(printf("received page with size %ld\n", res.size()));
            if (res.size() == PAGE_SIZE) {
                arg->content->data      = res;
            }
            arg->content->count--;
            // SIGNAL(arg->content->cond)
            UNLOCK(arg->content->mu)
            delete arg;
            return NULL;
        }, &args[i]);
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
        void * buf = mmap(nullptr, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, 
             this->swap_file_fd, VPID2VPADDR(relative_page_id));
        memcpy(buf, &arg_content->data[0], PAGE_SIZE);
        munmap(buf, PAGE_SIZE);
        succeed = true;
    }
    //DEBUG_STMT(printf("got rpc response %d\n", succeed));
    delete threads;
    delete arg_content;
    delete[] args;
    return succeed;
}

bool dsm_node::grant_write(char * addr) {
    page_id_t relative_page_id = relative_page_id_from_addr(addr);
    bool res = this->grant_prot(relative_page_id, DSM_PROT_WRITE);
    if (res) {
        LOCK(this->mu)
        this->page_info[relative_page_id] = DSM_PROT_WRITE;
        mprotect((void *)FLOOR((intptr_t)addr), PAGE_SIZE, PROT_READ | PROT_WRITE);
        UNLOCK(this->mu)
    }
    return res;
}

bool dsm_node::grant_read(char * addr) {
    page_id_t relative_page_id = relative_page_id_from_addr(addr);
    bool res = this->grant_prot(relative_page_id, DSM_PROT_READ);
    if (res) {
        LOCK(this->mu)
        this->page_info[relative_page_id] = DSM_PROT_READ;
        mprotect((void *)FLOOR((intptr_t)addr), PAGE_SIZE, PROT_READ);
        UNLOCK(this->mu)
    }
    return res;
}

dsm_node::dsm_node(node_addr m_addr, void * _base, size_t _len, bool is_master, int swapfd) {
    
    this->swap_file_fd = swapfd;
    //DEBUG_STMT(printf("is master %d\n", is_master));
    int pages = VPADDR2VPID(_len);
    page_info.resize(pages);
    for (int i = 0; i < pages; i++) {
        this->page_info[i] = is_master ? DSM_PROT_WRITE : DSM_PROT_INVALID;
    }
    this->base = (char *)_base;
    //DEBUG_STMT(printf("check mmap equal %lx\n", (intptr_t)this->base));
    ASSERT_PERROR(this->base);
    if (!is_master) {
        mprotect(_base, _len, PROT_NONE);
    }

    //DEBUG_STMT(printf("setup mem\n"));
    this->m_addr = m_addr;
    if (pthread_mutex_init(&this->mu, NULL)) {
        exit(-1);
    }
    serv = new rpc::server(m_addr.port);
    serv->bind(RPC_HAND_SHAKE, [this](node_addr src_addr) -> void {
        return this->respond_hand_shake(src_addr);
    });
    serv->bind(RPC_JOIN, [this]() -> vector<node_addr> {
        return this->respond_join();
    });
    serv->bind(RPC_WRITE, [this](uint64_t pagenum) -> page {
        return this->response_write(pagenum);
    });
    serv->bind(RPC_READ, [this](uint64_t pagenum) -> page {
        return this->response_read(pagenum);
    });
    dsm_singleton = this;
    pthread_create(&this->tid, NULL, [](void * input) -> void * {
        rpc::server * serv = (rpc::server *)input;
        serv->run();
        return nullptr;
    }, serv);
    //DEBUG_STMT(printf("run server\n"));
}




