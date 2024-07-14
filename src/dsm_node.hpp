#ifndef DSM_NODE
#define DSM_NODE

#include "rpc/server.h"
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <pthread.h>
#include <unordered_map>
#include <vector>

#define RELEASE_CONSISTANCY
#define PAGE_OFFSET_BIT 12
#define PAGE_SIZE (1 << PAGE_OFFSET_BIT)
#define VPID2VPADDR(vpid) ((vpid) << PAGE_OFFSET_BIT)
#define VPADDR2VPID(vpid) ((vpid) >> PAGE_OFFSET_BIT)

#define ASSERT(EXP, MSG)                                                        \
{                                                                               \
    if (!(EXP)) {                                                               \
        printf("ASSERTION FAILED at %s:%d: %s\n", __FILE__, __LINE__, MSG);     \
    }                                                                           \
}

#define ASSERT_PAGE_ALIGN(addr) ASSERT(((intptr)addr) % PAGE_SIZE == 0, "addr page align")
#define ASSERT_NOT_NULL(ptr) ASSERT(ptr, "null ptr error")
#define ASSERT_NOT_NULL_MSG(ptr, MSG) ASSERT(ptr, MSG)
#define ASSERT_POSIX_STATUS(status) ASSERT(status != -1, "posix error")

using namespace std;

typedef uint64_t page_id_t;

namespace dsm {
// init seg tree
// setup handler
void dsm_init();

struct node_addr {
    char ip[13];
    short port;
};

typedef vector<char> page;

class bit_mask {
#define SIZE2BYTE(x) (((x) + 7) >> 3)
#define MASK_OFFSET(x) (1 << (x))
    vector<char> mask;
public:
    bit_mask(size_t size) {
        mask = vector<char>(SIZE2BYTE(size));
    }
    bit_mask(size_t size, bool all_one) {
        mask = vector<char>(SIZE2BYTE(size), all_one ? -1 : 0);
    }
    bit_mask(vector<char> _mask) : mask(_mask) {}
    bool get(int x) {
        return mask[SIZE2BYTE(x)] & MASK_OFFSET(x % 8);
    }
    void set(int x) {
        mask[SIZE2BYTE(x)] |= MASK_OFFSET(x % 8);
    }
};

class dsm_node {
    char * base;
    string swap_file;
    int swap_file_fd;
    pthread_mutex_t mu;
    node_addr m_addr;
    vector<node_addr> conn;
    vector<char> page_info;
    page_id_t relative_page_id_from_addr(char * ptr) {
        return VPID2VPADDR(ptr - base);
    } 
    page_id_t relative_page_id_from_page_id(page_id_t page_id) {
        return page_id - VPADDR2VPID((intptr_t)this->base);
    } 
    void wait_recv();
    void add(int i, int k);
    void request_hand_shake(node_addr my_addr, node_addr dst_addr);
    void respond_hand_shake(node_addr src_addr);
    vector<node_addr> request_join(node_addr dst_addr);
    vector<node_addr> respond_join();
    page request_write(node_addr dst_addr, uint64_t pagenum);
    page response_write(uint64_t pagenum);
    page request_read(node_addr dst_addr, uint64_t pagenum);
    page response_read(uint64_t pagenum);
    bool grant_prot(void *base, int prot);
    rpc::server *serv;
public:
    dsm_node(node_addr m_addr, void *base, size_t len, 
             string swap_file = "", bool is_master = false);
    void connect(node_addr dst_addr);
    bool grant_write(void *base);
    bool grant_read(void *base);
};

} // namespace dsm
#endif
