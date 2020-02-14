#ifndef SMTP_H
#define SMTP_H

#include "smtp_caps.h"
#include "socktalk.h"
#include "socket.h"

typedef struct _server_credentials
{
   const char *account;     // e.g. "you@gmail.com"
   const char *host_url;    // e.g. "smtp.gmail.com" or "pop.gmail.com"
   int         host_port;   // e.g. 587 or 995

   const char *login;       // e.g. "you@gmail.com" (or copy pointer from account)
   const char *password;    // e.g. "abcdefghijklmnop"
} ServerCreds;

typedef enum _smtp_error_codes
{
   SMTP_SUCCESS = 0,
   SMTP_ERROR_NO_RESPONSE,
   SMTP_ERROR_AUTH_REFUSED,
   SMTP_ERROR_AUTH_LOGIN_REFUSED,
   SMTP_ERROR_AUTH_WRONG_PASSWORD
} SMTPError;


void init_server_creds(ServerCreds *sc);

int start_tls(ServerCreds *sc, STalker *open_talker, talker_user tuser);

int greet_smtp_server(SMTPCaps *scaps, const ServerCreds *sc, STalker *talker);




#endif

