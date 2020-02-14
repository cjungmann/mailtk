#include <stdio.h>

#include "mailtk.h"

#include "sample_creds.c"


void tls_user(STalker *stalker, void *data)
{
   ServerCreds *sc = (ServerCreds*)data;
   SMTPCaps scaps;

   if (greet_smtp_server(&scaps, sc, stalker))
   {
      printf("Established a TLS SMTP connection.\nThese are the available SMTP Caps:\n");
      show_smtpcaps(&scaps);
   }
   else
      printf("Failed to access SMTP server capabilities.\n");
}

void socket_user(STalker *stalker, void *data)
{
   ServerCreds *sc = (ServerCreds*)data;
   SMTPCaps scaps;

   if (greet_smtp_server(&scaps, sc, stalker))
   {
      if (scaps.cap_starttls)
         start_tls(sc, stalker, tls_user);
      else
      {
         printf("Using SMTP server without logging into it.\nThese are the available SMTP Caps:\n");
         show_smtpcaps(&scaps);
      }
   }
}


int main(int argc, const char **argv)
{
   ServerCreds sc;
   init_server_creds(&sc);

   const char *host_url = sc.host_url;
   int         host_port = sc.host_port;

   int exit_code = open_socket_talker(host_url, host_port, socket_user, &sc);
   if (exit_code)
      printf("Failed to open socket talker, %d.\n", exit_code);

   return 0;
}



