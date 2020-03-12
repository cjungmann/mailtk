#ifndef SOCKET_H
#define SOCKET_H

#include "socktalk.h"

typedef enum _mtk_socket_error
{
   MTKE_SUCCESS = 0,
   MTKE_INT_OVERFLOW,
   MTKE_UNKNOWN_HOST,
   MTKE_SOCKET_UNAVAILABLE,
   MTKE_UNBLOCKING_FAILURE,
   MTKE_CONNECTION_TIMEOUT
} MTK_ERROR;

typedef void (*talker_user)(STalker *talker, void *data);

MTK_ERROR open_socket_talker(const char *host_url, int host_port, void *data, talker_user callback);
void open_ssl_talker(STalker *open_talker, void *data, talker_user callback);

#endif



