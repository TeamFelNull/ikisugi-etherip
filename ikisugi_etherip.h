#ifndef IKISUGI_ETHERIP_H
#define IKISUGI_ETHERIP_H

#include <netdb.h>

#define IKISUGI_DOMAIN_INTERVAL 5

typedef void (*ikisugi_domain_change_callback)(struct sockaddr_storage *src_addr, struct sockaddr_storage *dst_addr);

extern struct sockaddr_storage ikisugi_src_addr;
extern struct sockaddr_storage ikisugi_dst_addr;

void ikisugi_handling_start(char *src_domain_, char *dst_domain_,
                  struct sockaddr_storage *src_addr, struct sockaddr_storage *dst_addr,
                  ikisugi_domain_change_callback callback);

int ikisugi_hostname_to_address(const char *host_name, int domain_type, struct sockaddr_storage *addr);

void ikisugi_text_sockaddr_storage(struct sockaddr_storage *str_addr, char text[], size_t size);

void ikisugi_copy_sockaddr_storage(struct sockaddr_storage *dest, struct sockaddr_storage *src);

#endif //IKISUGI_ETHERIP_H
