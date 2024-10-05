#ifndef DSM_NODE
#define DSM_NODE

#include "rpc/server.h"
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <pthread.h>
#include <rpc/msgpack/adaptor/define_decl.hpp>
#include <unordered_map>
#include <vector>

#define RELEASE_CONSISTANCY
#define PAGE_OFFSET_BIT 12
#define PAGE_SIZE (1 << PAGE_OFFSET_BIT)
#define VPID2VPADDR(vpid) ((vpid) << PAGE_OFFSET_BIT)
#define VPADDR2VPID(vpaddr) ((vpaddr) >> PAGE_OFFSET_BIT)

#define ASSERT(EXP, MSG)                                                       \
{                                                                            \
    if (!(EXP)) {                                                              \
        printf("ASSERTION FAILED at %s:%d: %s\n", __FILE__, __LINE__, MSG);      \
        exit(-1);                                                                \
    }                                                                          \
}

#define ASSERT_PAGE_ALIGN(addr)                                                \
ASSERT(((intptr)addr) % PAGE_SIZE == 0, "addr page align")
#define ASSERT_NOT_NULL(ptr) ASSERT(ptr, "null ptr error")
#define ASSERT_NOT_NULL_MSG(ptr, MSG) ASSERT(ptr, MSG)
#define ASSERT_POSIX_STATUS(status) ASSERT(status != -1, "posix error")
#define ASSERT_PERROR(err_no)                                                         \
{                                                                            \
    if ((int64_t)(err_no) == -1) {                                             \
        perror("POSIX ");                                                        \
        exit(-1);                                                                \
    }                                                                          \
}

using namespace std;

typedef uint64_t page_id_t;

namespace dsm {
// init seg tree
// setup handler

struct NodeAddr {
    string ip;
    short port;
    MSGPACK_DEFINE_ARRAY(ip, port);
};

void dsm_init();
char * dsm_init_master(NodeAddr self, size_t size);
char * dsm_init_node(NodeAddr self, NodeAddr dst, size_t size);

typedef vector<char> page;

class bit_mask {
#define SIZE2BYTE(x) (((x) + 7) >> 3)
#define MASK_OFFSET(x) (1 << (x))
    vector<char> mask;

public:
    bit_mask(size_t size) { mask = vector<char>(SIZE2BYTE(size)); }
    bit_mask(size_t size, bool all_one) {
        mask = vector<char>(SIZE2BYTE(size), all_one ? -1 : 0);
    }
    bit_mask(vector<char> _mask) : mask(_mask) {}
    bool get(int x) { return mask[SIZE2BYTE(x)] & MASK_OFFSET(x % 8); }
    void set(int x) { mask[SIZE2BYTE(x)] |= MASK_OFFSET(x % 8); }
};

class DSMNode {
    char *base;
    int swap_file_fd;
    pthread_mutex_t mu;
    NodeAddr m_addr;
    pthread_t tid;
    vector<NodeAddr> conn;
    vector<char> page_info;
    char *relative_page_id_to_addr(page_id_t page_id) {
        return this->base + VPID2VPADDR(page_id);
    }
    page_id_t relative_page_id_from_addr(char *ptr) {
        return VPADDR2VPID((intptr_t)ptr - (intptr_t)this->base);
    }
    page_id_t relative_page_id_from_page_id(page_id_t page_id) {
        return page_id - VPADDR2VPID((intptr_t)this->base);
    }
    void wait_recv();
    void add(int i, int k);
    void request_hand_shake(NodeAddr my_addr, NodeAddr dst_addr);
    void respond_hand_shake(NodeAddr src_addr);
    vector<NodeAddr> request_join(NodeAddr dst_addr);
    vector<NodeAddr> respond_join();
    page request_write(NodeAddr dst_addr, uint64_t pagenum);
    page response_write(uint64_t pagenum);
    page request_read(NodeAddr dst_addr, uint64_t pagenum);
    page response_read(uint64_t pagenum);
    bool grant_prot(page_id_t relative_page_id, int prot);
    rpc::server *serv;

public:
    DSMNode(NodeAddr m_addr, void *base, size_t len, 
             bool is_master, int swapfd);
    ~DSMNode() {
        if (!!tid)
            pthread_cancel(tid);
        if (!!serv)
            delete serv;
    }
    void sync();
    void connect(NodeAddr dst_addr);
    bool grant_write(char *addr);
    bool grant_read(char *addr);
    bool is_in_range(char *addr);
};

} // namespace dsm
#endif
