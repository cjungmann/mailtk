#ifndef SOCKET_H
#define SOCKET_H

#include "socktalk.h"

typedef void (*talker_user)(STalker *talker, void *data);

typedef struct _socket_handle
{
   STalker talker;
} SockHandle;

int open_socket_talker(const char *host_url, int host_port, talker_user tuser, void *data);

#endif



