#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <signal.h>
#include <linux/if.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <arpa/inet.h>

#include "etherip.h"
#include "tap.h"
#include "socket.h"
#include "ikisugi_etherip.h"

static pthread_t threads[THREAD_COUNT];
static pthread_barrier_t barrier;

struct etherip_hdr {
    uint8_t hdr_1st;
    uint8_t hdr_2nd;
};

struct recv_handlar_args {
    int domain;
    int sock_fd;
    int tap_fd;
    struct sockaddr_storage *dst_addr;
};

struct send_handlar_args {
    int domain;
    int sock_fd;
    int tap_fd;
    struct sockaddr_storage *dst_addr;
};

static void on_signal(int s){
    (void)s;
    pthread_kill(threads[0], SIGHUP);
    pthread_kill(threads[1], SIGHUP);
}

int global_tap_fd;
int global_sock_fd;

char global_tap_name[IFNAMSIZ];
int global_mtu = 1500;

static pthread_rwlock_t socket_rwlock;
int dst_domain;
struct sockaddr_storage dst_skaddr;

static void print_usage(){
    printf("Usage\n");
    printf("    etherip [OPTIONS] { ipv4 | ipv6 } dst <ip addr> src <ip addr> tap <tap if name> &\n");
    printf("OPTIONS\n");
    printf("    dst <ip addr>\t: set the destination ip address\n");
    printf("    src <ip addr>\t: set the source ip address\n");
    printf("    tap <tap if name>\t: set the tap IF name\n");
    printf("    --mtu <mtu>\t\t: set mtu (Not a tunnel IF mtu). default: 1500\n");

}

static void *recv_handlar(void *args){
    // setup
    // int domain = ((struct recv_handlar_args *)args)->domain;
    int sock_fd = ((struct recv_handlar_args *)args)->sock_fd;
    int tap_fd = ((struct recv_handlar_args *)args)->tap_fd;
    // struct sockaddr_storage *dst_addr = ((struct recv_handlar_args *)args)->dst_addr;
    
    ssize_t rlen;
    uint8_t buffer[BUFFER_SIZE];
    struct sockaddr_storage addr;
    socklen_t addr_len;
    uint8_t reserved1;
    uint8_t reserved2;
    struct iphdr *ip_hdr;
    int ip_hdr_len;
    struct etherip_hdr *hdr;
    uint8_t version;
    size_t write_len;
    // end setup
    pthread_barrier_wait(&barrier);

    while(1){
        pthread_rwlock_rdlock(&socket_rwlock);
        rlen = sock_read(sock_fd, buffer, sizeof(buffer), &addr, &addr_len);
        if(rlen == -1){
            // Failed to sock_read()
            return NULL;
        }

        
        if(dst_domain == AF_INET){
            if((size_t)rlen < sizeof(struct iphdr) + sizeof(struct etherip_hdr)){
                // too short
                continue;
            }

            // destination check
            struct sockaddr_in *dst_addr4;
            dst_addr4 = (struct sockaddr_in *)&dst_skaddr;
            struct sockaddr_in *addr4;
            addr4 = (struct sockaddr_in *)&addr;
            if(addr4->sin_addr.s_addr != dst_addr4->sin_addr.s_addr){
                continue;
            }

            // skip header
            ip_hdr = (struct iphdr *)buffer;
            ip_hdr_len = ip_hdr->ihl * 4;
            hdr = (struct etherip_hdr *)(buffer + ip_hdr_len);
            write_len = rlen - ETHERIP_HEADER_LEN - ip_hdr_len;
        }
        else if(dst_domain == AF_INET6){
            if((size_t)rlen < sizeof(struct ip6_hdr) + sizeof(struct etherip_hdr)){
                // too short
                continue;
            }

            // destination check
            struct sockaddr_in6 *dst_addr6;
            dst_addr6 = (struct sockaddr_in6 *)&dst_skaddr;
            struct sockaddr_in6 *addr6;
            addr6 = (struct sockaddr_in6 *)&addr;
            if(memcmp(addr6->sin6_addr.s6_addr, dst_addr6->sin6_addr.s6_addr, sizeof(addr6->sin6_addr.s6_addr)) != 0){
	            continue;
            }

            hdr = (struct etherip_hdr *)(&buffer);
            write_len = rlen - ETHERIP_HEADER_LEN;
        }


        // version check
        version = hdr->hdr_1st >> 4;
        if(version != ETHERIP_VERSION){
            // unknown version
            continue;
        }
        // reserved field check
        reserved1 = hdr->hdr_1st & 0xF;
        reserved2 = hdr->hdr_2nd;
        if(reserved1 != 0 || reserved2 != 0){
            // reserved field is not 0
            continue;
        }

        tap_write(tap_fd, (uint8_t *)(hdr+1), write_len);
        pthread_rwlock_unlock(&socket_rwlock);
    }

    return NULL;
}

static void *send_handlar(void *args){
    // setup
    // int domain = ((struct send_handlar_args *)args)->domain;
    int sock_fd = ((struct send_handlar_args *)args)->sock_fd;
    int tap_fd = ((struct send_handlar_args *)args)->tap_fd;
    //struct sockaddr_storage *dst_addr = ((struct send_handlar_args *)args)->dst_addr;
    size_t dst_addr_len;

    ssize_t rlen; // receive len
    uint8_t buffer[BUFFER_SIZE];
    uint8_t frame[BUFFER_SIZE];
    struct etherip_hdr *hdr;
    // end setup
    pthread_barrier_wait(&barrier);

    while(1){
        pthread_rwlock_rdlock(&socket_rwlock);
        rlen = tap_read(tap_fd, buffer, sizeof(buffer));
        if(rlen == -1){
            // Failed to tap_read()
            return NULL;
        }

        hdr = (struct etherip_hdr *)frame;
        hdr->hdr_1st = ETHERIP_VERSION << 4;
        hdr->hdr_2nd = 0;
        memcpy(hdr+1, buffer, rlen);
        if(dst_domain == AF_INET)
            dst_addr_len = sizeof( *(struct sockaddr_in *)&dst_skaddr );
        else if(dst_domain == AF_INET6){
            dst_addr_len = sizeof( *(struct sockaddr_in6 *)&dst_skaddr );
        }
        sock_write(sock_fd, frame, sizeof(struct etherip_hdr) + rlen, &dst_skaddr, dst_addr_len);
        pthread_rwlock_unlock(&socket_rwlock);
    }

    return NULL;
}

static void domain_change_callback(struct sockaddr_storage *src_addr, struct sockaddr_storage *dst_addr) {
    pthread_rwlock_wrlock(&socket_rwlock);

    sock_close(global_sock_fd);
    tap_close(global_tap_fd);

    dst_domain = dst_addr->ss_family;
    ikisugi_copy_sockaddr_storage(&dst_skaddr, dst_addr);

    if(tap_open(&global_tap_fd, global_tap_name, global_mtu, src_addr->ss_family) == -1){
        // Failed to tap_open()
        printf("Failed tap reopen!\n");
        exit(1);
    }
    printf("Tap reopen!\n");

    int len;

    if(src_addr->ss_family == AF_INET){
        struct sockaddr_in *src_addr4;
        src_addr4 = (struct sockaddr_in *)&src_addr;
        len =  sizeof(*src_addr4);
    }
    else if(src_addr->ss_family == AF_INET6){
        struct sockaddr_in6 *src_addr6;
        src_addr6 = (struct sockaddr_in6 *)&src_addr;
        len = sizeof(*src_addr6);
    }  

    if(sock_open(&global_sock_fd, src_addr->ss_family, src_addr, len) == -1){
        // Failed to sock_open()
        printf("Failed socket reopen!\n");
        exit(1);
    }

    printf("Socket reopen!\n");

    pthread_rwlock_unlock(&socket_rwlock);
}

int main(int argc, char **argv){
    signal(SIGINT, on_signal);

    if(argc == 1){
        print_usage();
        return 0;
    }

    int domain;
    char src[IPv6_ADDR_STR_LEN];
    char dst[IPv6_ADDR_STR_LEN];
    int required_arg_cnt;
    uint8_t use_domain_src = 0;
    uint8_t use_domain_dst = 0;

    // parse arguments
    required_arg_cnt = 0;
    for(int i = 1; i < argc; i++){
        if(strcmp(argv[i], "ipv4") == 0){
            required_arg_cnt++;
            domain = AF_INET;
        }    
        if(strcmp(argv[i], "ipv6") == 0){
            required_arg_cnt++;
            domain = AF_INET6;
        }
        if(strcmp(argv[i], "dst") == 0){
            required_arg_cnt++;
            strcpy(dst, argv[++i]);
        }
        if(strcmp(argv[i], "src") == 0){
            required_arg_cnt++;
            strcpy(src, argv[++i]);
        }
        if(strcmp(argv[i], "tap") == 0){
            required_arg_cnt++;
            strcpy(global_tap_name, argv[++i]);
        }
        if(strcmp(argv[i], "--mtu") == 0){
            global_mtu = atoi(argv[++i]);
        }
        if(strcmp(argv[i], "-h") == 0){
            print_usage();
            return 0;
        }
        if(strcmp(argv[i], "-srcdom") == 0){
            use_domain_src = 1;
        }
        if(strcmp(argv[i], "-dstdom") == 0){
            use_domain_dst = 1;
        }
    }
    if(required_arg_cnt != 4){
        printf("[ERROR]: Too few or too many arguments required.\n");
        printf("Help: etherip -h\n");
        return 0;
    }

    // init
    if(tap_open(&global_tap_fd, global_tap_name, global_mtu, domain) == -1){
        // Failed to tap_open()
        return 0;
    }

    struct sockaddr_storage src_addr;
    socklen_t sock_len;
    char addr_text[1024];

    if(use_domain_src){
        if(ikisugi_hostname_to_address(src, domain, &src_addr) != 0){
            printf("IP acquisition failure! (%s)\n",src);
            return 0;
        }

        ikisugi_text_sockaddr_storage(&src_addr, addr_text, 1024);
        printf("Domain IP: %s -> %s\n", src, addr_text);

        if(domain == AF_INET){
            struct sockaddr_in *src_addr4;
            src_addr4 = (struct sockaddr_in *)&src_addr;
            sock_len =  sizeof(*src_addr4);
        }
        else if(domain == AF_INET6){
            struct sockaddr_in6 *src_addr6;
            src_addr6 = (struct sockaddr_in6 *)&src_addr;
            sock_len = sizeof(*src_addr6);
        }  
    } 
    else {
        if(domain == AF_INET){
            struct sockaddr_in *src_addr4;
            src_addr4 = (struct sockaddr_in *)&src_addr;
    
            src_addr4->sin_family = AF_INET;
            inet_pton(AF_INET, src, &src_addr4->sin_addr.s_addr);
            src_addr4->sin_port  = htons(ETHERIP_PROTO_NUM);
            sock_len =  sizeof(*src_addr4);
        }
        else if(domain == AF_INET6){
            struct sockaddr_in6 *src_addr6;
            src_addr6 = (struct sockaddr_in6 *)&src_addr;
    
            src_addr6->sin6_family = AF_INET6;
            inet_pton(AF_INET6, src, &src_addr6->sin6_addr.s6_addr);
            src_addr6->sin6_port = htons(ETHERIP_PROTO_NUM);
            sock_len = sizeof(*src_addr6);
        }  
    }
    
    if(sock_open(&global_sock_fd, domain, &src_addr, sock_len) == -1){
        // Failed to sock_open()
        return 0;
    }
    
    struct sockaddr_storage dst_addr;

    if(use_domain_src){
        if(ikisugi_hostname_to_address(dst, domain, &dst_addr) != 0){
            printf("IP acquisition failure! (%s)\n",dst);
            return 0;
        }

        ikisugi_text_sockaddr_storage(&dst_addr, addr_text, 1024);
        printf("Domain IP: %s -> %s\n", dst, addr_text);
    } 
    else {
        if(domain == AF_INET){
            struct sockaddr_in *dst_addr4;
            dst_addr4 = (struct sockaddr_in *)&dst_addr;

            dst_addr4->sin_family = AF_INET;
            inet_pton(AF_INET, dst, &dst_addr4->sin_addr.s_addr);
            dst_addr4->sin_port  = htons(ETHERIP_PROTO_NUM);
        }
        else if(domain == AF_INET6){
            struct sockaddr_in6 *dst_addr6;
            dst_addr6 = (struct sockaddr_in6 *)&dst_addr;

            dst_addr6->sin6_family = AF_INET6;
            inet_pton(AF_INET6, dst, &dst_addr6->sin6_addr.s6_addr);
	        dst_addr6->sin6_port = htons(ETHERIP_PROTO_NUM);
        }    
    }

    // start threads
    pthread_barrier_init(&barrier, NULL, 2);
    pthread_rwlock_init(&socket_rwlock, NULL);

    struct recv_handlar_args recv_args = {domain, global_sock_fd, global_tap_fd, &dst_addr};
    pthread_create(&threads[0], NULL, recv_handlar, &recv_args);
    struct send_handlar_args send_args = {domain, global_sock_fd, global_tap_fd, &dst_addr};
    pthread_create(&threads[1], NULL, send_handlar, &send_args);

    fprintf(stdout, "[INFO]: Started etherip. dst: %s src: %s\n", dst, src);

    if(use_domain_src || use_domain_dst){
        ikisugi_handling_start(use_domain_src ? src : NULL, use_domain_dst ? dst : NULL, &src_addr, &dst_addr, domain_change_callback);
    }

    if(pthread_join(threads[0], NULL) == 0){
        fprintf(stderr, "[ERROR]: Stopped recv_handlar\n");
        pthread_kill(threads[1], SIGHUP);
        fprintf(stderr, "[ERROR]: Stopped etherip\n");
    }
    if(pthread_join(threads[1], NULL) == 0){
        fprintf(stderr, "[ERROR]: Stopped send_handlar\n");
        pthread_kill(threads[0], SIGHUP);
        fprintf(stderr, "[ERROR]: Stopped etherip\n");
    }

    pthread_barrier_destroy(&barrier);
    pthread_rwlock_destroy(&socket_rwlock);

    // cleanup
    sock_close(global_sock_fd);
    tap_close(global_tap_fd);

    return 0;
}