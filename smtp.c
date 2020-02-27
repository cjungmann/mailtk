// -*- compile-command: "base=smtp; gcc -Wall -Werror -ggdb -DSMTP_MAIN -DDEBUG -o $base ${base}.c -lssl -lcrypto -lcode64" -*-

#include <string.h>
#include <ctype.h>  // for isspace()
#include <code64.h>

#include "smtp.h"
#include "smtp_caps.h"

int read_complete_ehlo_response(STalker *talker, char *buffer, int buff_len)
{
   char *ptr = buffer;
   char *end_of_buffer = buffer + buff_len;
   char *end_of_data;
   size_t read;

   int line_status;

   char *cur_line = buffer;
   char *end_cur_line;

   while (ptr < end_of_buffer)
   {
      read = stk_recv_line(talker, ptr, end_of_buffer - ptr);
      end_of_data = ptr + read;

      // Read complete lines, detect line with space between
      // the status number and the message: that's the last line.

      while (cur_line < end_of_data)
      {
         end_cur_line = cur_line;
         while (end_cur_line < end_of_data && *end_cur_line != '\r')
            ++end_cur_line;

         // If we have a complete line, judge if it's the last
         if (end_cur_line < end_of_data)
         {
            // If good line, set cur_line to beginning of next line
            line_status = atoi(cur_line);
            if (line_status >= 400)
            {
               fprintf(stderr,
                       "Request failure detected with line_status == %d (%s)\n",
                       line_status,
                       cur_line);

               goto found_end_of_data;
            }

            if (line_status == 250 && cur_line[3] == ' ')
               goto found_end_of_data;
            else
            {
               cur_line = end_cur_line;
               while (cur_line < end_of_data && isspace(*cur_line))
                   ++cur_line;
            }
         }
         else  // If not a complete line, break while() to retrieve another batch of bytes
            break;
      }

      ptr += read;
   }

  found_end_of_data:
   return end_of_data - buffer;
}

int start_tls(talker_user callback, STalker *open_talker, void *data)
{
   char buffer[1024];
   int bytes_read;
   stk_send_line(open_talker, "STARTTLS", NULL);

   /* bytes_read = read_complete_ehlo_response(talker, buffer, sizeof(buffer)); */
   bytes_read = stk_recv_line(open_talker, buffer, sizeof(buffer));
   if (bytes_read > 3)
   {
      open_ssl_talker(open_talker, data, callback);
      return 1;
   }

   return 0;
}

int greet_smtp_server(SMTPCaps *scaps, const char *host_url, STalker *talker)
{
   char buffer[1024];
   
   memset(scaps, 0, sizeof(SMTPCaps));

   stk_send_line(talker, "EHLO ", host_url, NULL);

   int bytes_read = read_complete_ehlo_response(talker, buffer, sizeof(buffer));
   if (bytes_read)
   {
      parse_ehlo_response(scaps, buffer, bytes_read);
      return 1;
   }

   return 0;
}

int authorize_with_login(const char *login, const char *password, STalker *stalker)
{
   char buffer[1024];
   int bytes_received = 0;
   int reply_status;

   stk_send_line(stalker, "AUTH LOGIN", NULL);
   bytes_received = stk_recv_line(stalker, buffer, sizeof(buffer));
   if (bytes_received)
   {
      buffer[bytes_received] = '\0';
      reply_status = atoi(buffer);

      if (reply_status >= 300 && reply_status < 400)
      {
         c64_encode_to_buffer(login, strlen(login), (uint32_t*)&buffer, sizeof(buffer));

         stk_send_line(stalker, buffer, NULL);
         bytes_received = stk_recv_line(stalker, buffer, sizeof(buffer));
         buffer[bytes_received] = '\0';
         reply_status = atoi(buffer);

         if (reply_status >= 300 && reply_status < 400)
         {
            c64_encode_to_buffer(password, strlen(password), (uint32_t*)&buffer, sizeof(buffer));

            stk_send_line(stalker, buffer, NULL);
            bytes_received = stk_recv_line(stalker, buffer, sizeof(buffer));
            buffer[bytes_received] = '\0';
            reply_status = atoi(buffer);

            if (reply_status >= 200 && reply_status < 300)
               return SMTP_SUCCESS;
            else
               return SMTP_ERROR_AUTH_WRONG_PASSWORD;
         }
         else
            return SMTP_ERROR_AUTH_LOGIN_REFUSED;
      }
      else
         return SMTP_ERROR_AUTH_REFUSED;
   }
   else
      return SMTP_ERROR_NO_RESPONSE;

   return 0;
}


#ifdef SMTP_MAIN

/**
 * sample_creds.c is not part of the project: it holds
 * sensitive data that permits using an SMTP account.
 * If you choose to use it, you will have to provide the
 * appropriate values.
 *
 * sample_creds.c should contain a function that prepares
 * a ServerCreds object.  Alternatively, the call to
 * init_server_creds() could be replaced with code that
 * sets the ServerCreds object by another means.
 *
 * void init_server_creds(ServerCreds *sc)
 * {
 *    memset(sc, 0, sizeof(ServerCreds));
 *    sc->host_url = "smtp.gmail.com";
 *    sc->host_port = 587;
 *    sc->account = "bogus@gmail.com";
 *
 *    sc->login = sc->account;
 *    sc->password = "bogus_password";
 * }
 * 
 */


#include "sample_creds.c"

// Include source files for one-off compile
#include "socktalk.c"
#include "socket.c"
#include "smtp_caps.c"
#include "logging.c"

void use_the_smtp_tls_talker(STalker *stalker, void *data)
{
   SMTPCaps scaps;
   ServerCreds *sc = (ServerCreds*)data;
   SMTPError serror;
   if (greet_smtp_server(&scaps, sc->host_url, stalker))
   {
      if (cget_auth_login(&scaps))
      {
         serror = authorize_with_login(sc->login, sc->password, stalker);
         if (serror)
            printf("Authorization failed with %d.\n", serror);
         else
            printf("Successfully logged in with PLAIN authorization.\n");
      }
      else
         show_smtpcaps(&scaps);
   }
}


void use_the_smtp_talker(STalker *stalker, void *data)
{
   ServerCreds *sc = (ServerCreds*)data;
   SMTPCaps scaps;

   if (greet_smtp_server(&scaps, sc->host_url, stalker))
   {
      show_smtpcaps(&scaps);
      printf("About to start_tls.\n");
      start_tls(stalker, data, use_the_smtp_tls_talker);
   }
   else
      printf("There was a problem with greet_smtp_server().\n");

   // Terminate the connection
   char buffer[1024];
   stk_send_line(stalker, "QUIT", NULL);
   stk_recv_line(stalker, buffer, sizeof(buffer));
}

int main(int argc, const char **argv)
{
   ServerCreds sc;
   init_server_creds(&sc);

   int exit_code = open_socket_talker(sc.host_url, sc.host_port, &sc, use_the_smtp_talker);
   if (exit_code)
   {
      fprintf(stderr,
              "Failed to open socket for %s:%d: (%d) %s.\n",
              sc.host_url,
              sc.host_port,
              exit_code,
              gai_strerror(exit_code));
   }   
}



#endif
