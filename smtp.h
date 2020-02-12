#ifndef SMTP_H
#define SMTP_H

#include "smtp_setcaps.h"
#include "socktalk.h"

typedef struct _server_credentials
{
   const char *account;
   const char *host_url;
   int         host_port;

   const char *login;
   const char *password;
} ServerCreds;


void init_server_creds(ServerCreds *sc);

int greet_smtp_server(SMTPCaps *scaps, const ServerCreds *sc, STalker *talker);




#endif

