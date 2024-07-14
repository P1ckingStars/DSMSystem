#include "dsm_node.hpp"
#include "rpc/client.h"
#include "syncheader.hpp"
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <pthread.h>
#include <sstream>
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
    printf("Got SIGSEGV at address: 0x%lx\n", (long)si->si_addr);
    if (is_write && dsm_singleton->grant_write(si->si_addr)) {
        mprotect((void *)FLOOR((intptr_t)si->si_addr), PAGE_SIZE, PROT_READ | PROT_WRITE);
    } else if (!is_write && dsm_singleton->grant_read(si->si_addr)) {
        mprotect((void *)FLOOR((intptr_t)si->si_addr), PAGE_SIZE, PROT_READ);
    }
}

void dsm_init() {
    struct sigaction sa;
    sa.sa_flags = SA_SIGINFO;
    sigemptyset(&sa.sa_mask);
    sa.sa_sigaction = handler;
    if (sigaction(SIGSEGV, &sa, NULL) == -1) {
        printf("can't customize SEGV handler\n");
        exit(-1);
    }
}

void dsm_node::request_hand_shake(node_addr my_addr, node_addr dst_addr) {
    rpc::client cli(dst_addr.ip, dst_addr.port);
    cli.call(RPC_HAND_SHAKE, m_addr);
}

void dsm_node::respond_hand_shake(node_addr src_addr) {
    this->conn.push_back(src_addr);
}

vector<node_addr> dsm_node::request_join(node_addr dst_addr) {
    rpc::client cli(dst_addr.ip, dst_addr.port);
    return cli.call(RPC_JOIN, m_addr).as<vector<node_addr>>();
}
vector<node_addr> dsm_node::respond_join() {
    return this->conn;
}

page dsm_node::request_write(node_addr dst_addr, uint64_t pagenum) {
    rpc::client cli(dst_addr.ip, dst_addr.port);
    return cli.call(RPC_WRITE, pagenum).as<page>();
    
}

page dsm_node::response_write(uint64_t pagenum) {
    page res;
    res.clear();
    page_id_t relative_page_id = relative_page_id_from_page_id(pagenum);
    LOCK(this->mu)
    if (this->page_info.size() > relative_page_id 
        && READABLE(this->page_info[relative_page_id])) {
        if (OWNERSHIP(this->page_info[relative_page_id])) {
            res.resize(PAGE_SIZE);
            memcpy(&res[0], (void *)VPID2VPADDR(pagenum), PAGE_SIZE);
        }
#ifdef RELEASE_CONSISTANCY
        this->page_info[relative_page_id] = DSM_PROT_READ;
#else 
        this->page_info[relative_page_id] = 0;
        mprotect((void *)VPID2VPADDR(pagenum), PAGE_SIZE, PROT_NONE);
#endif
    }
    UNLOCK(this->mu)
    return res;   
}

page dsm_node::request_read(node_addr dst_addr, uint64_t pagenum) {
    rpc::client cli(dst_addr.ip, dst_addr.port);
    return cli.call(RPC_READ, pagenum).as<page>();
}

page dsm_node::response_read(uint64_t pagenum) {
    page res;
    res.clear();
    page_id_t relative_page_id = relative_page_id_from_page_id(pagenum); 
    LOCK(this->mu)
    if (this->page_info.size() > relative_page_id
        && OWNERSHIP(this->page_info[relative_page_id])) {
        memcpy(&res[0], (void *)VPID2VPADDR(pagenum), PAGE_SIZE);
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
    int                     base;
    int                     prot;
};


bool dsm_node::grant_prot(void *base, int prot) {
    page res;
    pthread_t * threads                 = (pthread_t *)malloc(sizeof(pthread_t) * this->conn.size());
    thread_arg_content * arg_content    = new thread_arg_content();
    arg_content->self                   = this;
    arg_content->data.clear();
    thread_arg * args                   = new thread_arg[this->conn.size()];
    page_id_t page_id                   = VPADDR2VPID((intptr_t)base);
    pthread_mutex_init(&arg_content->mu, NULL);
    pthread_cond_init(&arg_content->cond, NULL);
    for (int i = 0; i < this->conn.size(); i++) {
        args[i].content                 = arg_content;
        args[i].idx                     = i;
        args[i].base                    = page_id;
        args[i].prot                    = prot;
        pthread_create(&threads[i], NULL, [](void * input) -> void * {
            thread_arg * arg            = (thread_arg *)input;
            auto self                   = arg->content->self;
            auto res                    = arg->prot == DSM_PROT_READ ?
                self->request_read(self->conn[arg->idx], arg->base) :
                self->request_write(self->conn[arg->idx], arg->base);
            LOCK(arg->content->mu)
            if (res.size() == PAGE_SIZE) {
                arg->content->data      = res;
                arg->content->count--;
            }
            SIGNAL(arg->content->cond)
            UNLOCK(arg->content->mu)
            delete arg;
            return NULL;
        }, args + i);
    }
    LOCK(arg_content->mu)
#ifdef RELEASE_CONSISTANCY
    while (arg_content->data.size() != PAGE_SIZE && arg_content->count) {
        WAIT(arg_content->cond, arg_content->mu)
    }
    for (int i = 0; i < this->conn.size(); i++) {
        pthread_cancel(threads[i]);
    }
#else
    for (int i = 0; i < this->conn.size(); i++) {
        pthread_join(threads[i]);
    }
#endif
    bool succeed = false;
    if (arg_content->data.size() == PAGE_SIZE) {
        void * buf = mmap(nullptr, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, 
             this->swap_file_fd, VPID2VPADDR(page_id)-(intptr_t)this->base);
        memcpy(buf, &arg_content->data[0], PAGE_SIZE);
        munmap(buf, PAGE_SIZE);
        succeed = true;
    }
    UNLOCK(arg_content->mu)
    delete threads;
    delete arg_content;
    delete[] args;
    return succeed;
}

bool dsm_node::grant_write(void * base) {
    return this->grant_prot(base, DSM_PROT_WRITE);
}

bool dsm_node::grant_read(void * base) {
    return this->grant_prot(base, DSM_PROT_READ);
}

dsm_node::dsm_node(node_addr m_addr, void * _base, size_t _len, string _swap_file, bool is_master) {
    if (!_swap_file.size()) {
        stringstream ss;
        ss << ".swap" << random();
        this->swap_file = ss.str();
    } else this->swap_file = _swap_file;
    this->swap_file_fd = open(this->swap_file.c_str(), O_TMPFILE | O_RDWR, 0x666);
    ASSERT_POSIX_STATUS(this->swap_file_fd);
    char buf[PAGE_SIZE];
    int pages = VPADDR2VPID(_len);
    for (int i = 0; i < pages; i++) {
        ASSERT_POSIX_STATUS(write(swap_file_fd, buf, PAGE_SIZE));
        this->page_info[i] = DSM_PROT_WRITE;
    }
    this->base = (char *)mmap(_base, _len, 
                              is_master ? (PROT_WRITE | PROT_READ) : PROT_NONE, MAP_SHARED, 
                              swap_file_fd, 0);
    ASSERT_NOT_NULL(this->base);

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
    serv->run();
}




