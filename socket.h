#ifndef SOCKET_H
#define SOCKET_H

#include "socktalk.h"

typedef void (*talker_user)(STalker *talker, void *data);

typedef struct _socket_handle
{
   STalker talker;
} SockHandle;

int open_socket_talker(talker_user callback, const char *host_url, int host_port, void *data);
void open_ssl_talker(talker_user callback, STalker *open_talker, void *data);

#endif



