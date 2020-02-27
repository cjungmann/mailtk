#ifndef SOCKET_H
#define SOCKET_H

#include "socktalk.h"

typedef void (*talker_user)(STalker *talker, void *data);

int open_socket_talker(const char *host_url, int host_port, void *data, talker_user callback);
void open_ssl_talker(STalker *open_talker, void *data, talker_user callback);

#endif



