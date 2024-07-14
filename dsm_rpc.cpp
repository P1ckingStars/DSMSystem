#include "dsm_rpc.hpp"
#include <bits/stdc++.h> 
#include <cstdlib>
#include <iostream>
#include <pthread.h>
#include <stdlib.h> 
#include <unistd.h> 
#include <string.h> 
#include <sys/types.h> 
#include <sys/socket.h> 
#include <arpa/inet.h> 
#include <netinet/in.h>

using namespace dsm;
using namespace std;

inline void panic(string s) {
    cout << s << endl;
    exit(-1);
}

tcp_rpc_node::tcp_rpc_node(short port, rpc_dispatcher * dispatcher) : rpc_node(port, dispatcher) {
    int connfd = 0;
    struct sockaddr_in serv_addr; 

    char sendBuff[1025];
    time_t ticks; 

    listenfd = socket(AF_INET, SOCK_STREAM, 0);
    memset(&serv_addr, '0', sizeof(serv_addr));
    memset(sendBuff, '0', sizeof(sendBuff)); 

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    serv_addr.sin_port = htons(5000); 

    if (-1 == bind(listenfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr))) {

    }
    if (listen(listenfd, 30) < 0) {

    }
}
rpc_proto tcp_rpc_node::rpc_request(rpc_proto const &msg, sockaddr const &saddr) {

}
void tcp_rpc_node::rpc_respond(rpc_proto const &msg, sockaddr const &saddr) {

}

void * tcp_rpc_run(void * input) {
    ideal_udp_rpc_node * self = (ideal_udp_rpc_node *)input;
    while (1) {
        sockaddr cliaddr;
        socklen_t len;
        int n; 
        len = sizeof(cliaddr);  //len is value/result 
    }
}

sockaddr tcp_rpc_node::run() {
    pthread_t pid;
    pthread_create(&pid, NULL, tcp_rpc_run, this);
}















