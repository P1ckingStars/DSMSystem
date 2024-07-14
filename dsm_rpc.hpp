#ifndef DSM_RPC_HPP
#define DSM_RPC_HPP

#include <cstddef>
#include <sys/socket.h>

namespace dsm {

struct rpc_proto {
    sockaddr sender;
    int func_id;
    size_t buf_size;
    void *buf;
};

class rpc_dispatcher {
public:
    virtual rpc_proto dispatch(rpc_proto const & msg, 
                               sockaddr const &saddr) = 0;
};

class rpc_node {
protected:
    sockaddr saddr;
    rpc_dispatcher * dispatcher;
public:
    rpc_node(short port, rpc_dispatcher * dispatcher) { 
        this->dispatcher = dispatcher;
    }
    virtual rpc_proto rpc_request(rpc_proto const &msg,
                                  sockaddr const &saddr) = 0;
    virtual void rpc_respond(rpc_proto const &msg, sockaddr const &saddr) = 0;
    virtual sockaddr run() = 0;
};

class tcp_rpc_node: rpc_node {
    int listenfd;
public:
    tcp_rpc_node(short port, rpc_dispatcher * dispatcher);
    rpc_proto rpc_request(rpc_proto const &msg,
                                  sockaddr const &saddr);
    void rpc_respond(rpc_proto const &msg, sockaddr const &saddr);
    sockaddr run();
};

class ideal_udp_rpc_node: rpc_node {
public:
    ideal_udp_rpc_node(short port, rpc_dispatcher * dispatcher);
    rpc_proto rpc_request(rpc_proto const &msg,
                                  sockaddr const &saddr);
    void rpc_respond(rpc_proto const &msg, sockaddr const &saddr);
    sockaddr run();
};

}
#endif
