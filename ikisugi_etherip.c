#include <stdio.h>
#include <pthread.h>
#include <unistd.h>
#include <stdint.h>

#include "ikisugi_etherip.h"

#define  TEXT_BUFF_SIZE 1024

#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#define IPV4_ADDR(a) (((struct sockaddr_in *) (a))->sin_addr.s_addr)
#define IPV6_ADDR(a) (((struct sockaddr_in6 *) (a))->sin6_addr.s6_addr)

typedef struct {
    struct sockaddr_storage *ikisugi_addr;
    struct sockaddr_storage tmp_addr;
    struct sockaddr_storage last_addr;
} check_addresses;

struct sockaddr_storage ikisugi_src_addr;
struct sockaddr_storage ikisugi_dst_addr;

static ikisugi_domain_change_callback domain_change_callback;

static char *src_domain;
static char *dst_domain;
static pthread_t domain_handler_thread;

static char old_addr_text[TEXT_BUFF_SIZE];
static char new_addr_text[TEXT_BUFF_SIZE];

static check_addresses src_check_addresses;
static check_addresses dst_check_addresses;

void ikisugi_copy_sockaddr_storage(struct sockaddr_storage *dest, struct sockaddr_storage *src) {
    if (AF_INET == src->ss_family) {
        dest->ss_family = AF_INET;
        IPV4_ADDR(dest) = IPV4_ADDR(src);
    } else if (AF_INET6 == src->ss_family) {
        dest->ss_family = AF_INET6;
        memcpy(IPV6_ADDR(dest), IPV6_ADDR(src), sizeof(IPV6_ADDR(dest)));
    }
}

static uint8_t equal_sockaddr_storage(struct sockaddr_storage *target1, struct sockaddr_storage *taget2) {
    if (target1->ss_family != taget2->ss_family) {
        return 0;
    }

    if (AF_INET == target1->ss_family) {
        if (IPV4_ADDR(target1) == IPV4_ADDR(taget2)) {
            return 1;
        }
    } else if (AF_INET6 == target1->ss_family) {
        if (memcmp(IPV6_ADDR(target1), IPV6_ADDR(taget2), sizeof(IPV6_ADDR(target1))) == 0) {
            return 1;
        }
    }

    return 0;
}

void ikisugi_text_sockaddr_storage(struct sockaddr_storage *str_addr, char text[], size_t size) {
    if (AF_INET == str_addr->ss_family) {
        inet_ntop(str_addr->ss_family, &((struct sockaddr_in *) str_addr)->sin_addr, text, size);
    } else if (AF_INET6 == str_addr->ss_family) {
        inet_ntop(str_addr->ss_family, &((struct sockaddr_in6 *) str_addr)->sin6_addr, text, size);
    }
}

int ikisugi_hostname_to_address(const char *host_name, int domain_type, struct sockaddr_storage *addr) {
    if (AF_INET != domain_type && AF_INET6 != domain_type) {
        return 1;
    }

    struct addrinfo hints, *ret_info;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = domain_type;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(host_name, NULL, &hints, &ret_info) != 0) {
        return 1;
    }

    int ret;
    if (AF_INET == ret_info->ai_family) {
        addr->ss_family = AF_INET;
        IPV4_ADDR(addr) = IPV4_ADDR(ret_info->ai_addr);
        ret = 0;
    } else if (AF_INET6 == ret_info->ai_family) {
        addr->ss_family = AF_INET6;
        memcpy(IPV6_ADDR(addr), IPV6_ADDR(ret_info->ai_addr), sizeof(IPV6_ADDR(addr)));
        ret = 0;
    } else {
        ret = 1;
    }

    freeaddrinfo(ret_info);
    return ret;
}

static void domain_check(char *host_name, struct sockaddr_storage *addr, check_addresses *check_addresses) {
    int hta_ret = ikisugi_hostname_to_address(host_name, check_addresses->ikisugi_addr->ss_family,
                                              &check_addresses->tmp_addr);

    if (hta_ret != 0) {
        printf("IP acquisition failure!\n");
        return;
    }

    if (!equal_sockaddr_storage(&check_addresses->last_addr, &check_addresses->tmp_addr)) {

        ikisugi_text_sockaddr_storage(check_addresses->ikisugi_addr, old_addr_text, ARRAY_SIZE(old_addr_text));
        ikisugi_text_sockaddr_storage(&check_addresses->tmp_addr, new_addr_text, ARRAY_SIZE(new_addr_text));

        printf("IP Update!\n");
        printf("%s %s -> %s\n", host_name, old_addr_text, new_addr_text);

        ikisugi_copy_sockaddr_storage(check_addresses->ikisugi_addr, &check_addresses->tmp_addr);

        domain_change_callback(&ikisugi_src_addr, &ikisugi_dst_addr);
    }

    ikisugi_copy_sockaddr_storage(&check_addresses->last_addr, &check_addresses->tmp_addr);
}

static void *domain_handler(void *args) {
    for (;;) {
        sleep(IKISUGI_DOMAIN_INTERVAL);

        if (src_domain != NULL) {
            domain_check(src_domain, &ikisugi_src_addr, &src_check_addresses);
        }

        if (dst_domain != NULL) {
            domain_check(dst_domain, &ikisugi_dst_addr, &dst_check_addresses);
        }
    }
}

void ikisugi_handling_start(char *src_domain_, char *dst_domain_,
                            struct sockaddr_storage *src_addr, struct sockaddr_storage *dst_addr,
                            ikisugi_domain_change_callback callback) {
    printf("Ikisugi Handling Start!\n");

    src_domain = src_domain_;
    dst_domain = dst_domain_;

    ikisugi_copy_sockaddr_storage(&ikisugi_src_addr, src_addr);
    ikisugi_copy_sockaddr_storage(&ikisugi_dst_addr, dst_addr);

    src_check_addresses.ikisugi_addr = &ikisugi_src_addr;
    dst_check_addresses.ikisugi_addr = &ikisugi_dst_addr;

    ikisugi_copy_sockaddr_storage(&src_check_addresses.last_addr, &ikisugi_src_addr);
    ikisugi_copy_sockaddr_storage(&dst_check_addresses.last_addr, &ikisugi_dst_addr);
    ikisugi_copy_sockaddr_storage(&src_check_addresses.tmp_addr, &ikisugi_src_addr);
    ikisugi_copy_sockaddr_storage(&dst_check_addresses.tmp_addr, &ikisugi_dst_addr);

    domain_change_callback = callback;

    pthread_create(&domain_handler_thread, NULL, domain_handler, NULL);
}