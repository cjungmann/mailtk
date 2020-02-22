#include <stdio.h>
#include <errno.h>   // for errno to discern extended errors
#include <string.h>  // for memcopy(), strerror(), etc;
#include <alloca.h>

#include <netdb.h>       // For getaddrinfo() and supporting structures
#include <arpa/inet.h>   // Functions that convert addrinfo member values.
#include <unistd.h>      // for close() function

#include <assert.h>

#include "socktalk.h"
#include "socket.h"
#include "logging.h"

int digits_in_base(int value, int base)
{
   int count = 0;
   while (value > 0)
   {
      ++count;
      value /= base;
   }

   return count;
}

int itoa_buff(int value, int base, char *buffer, int buffer_len)
{
   int output_length = digits_in_base(value, base);

   if (output_length < buffer_len)
   {
      memset(buffer, 0, buffer_len);
      char *ptr = &buffer[output_length-1];

      while (value > 0)
      {
         *ptr = (value % base) + '0';
         --ptr;
         value /= base;
      }

      return 1;
   }
   else
      return 0;
}


/**
 * @brief Creates a readable message from SSL_get_error() for logging an error.
 */
void log_ssl_error(const SSL *ssl, int return_value)
{
   int error = SSL_get_error(ssl, return_value);
   const char *msg = NULL;
   switch(error)
   {
      case SSL_ERROR_NONE:
         msg = "SSL_ERROR_NONE";
         break;

      case SSL_ERROR_ZERO_RETURN:
         msg = "SSL_ERROR_ZERO_RETURN";
         break;
      case SSL_ERROR_WANT_READ:
         msg = "SSL_ERROR_WANT_READ";
         break;
      case SSL_ERROR_WANT_WRITE:
         msg = "SSL_ERROR_WANT_WRITE";
         break;
      case SSL_ERROR_WANT_CONNECT:
         msg = "SSL_ERROR_WANT_CONNECT";
         break;
      case SSL_ERROR_WANT_ACCEPT:
         msg = "SSL_ERROR_WANT_ACCEPT";
         break;
      case SSL_ERROR_WANT_X509_LOOKUP:
         msg = "SSL_ERROR_WANT_X509_LOOKUP";
         break;
      case SSL_ERROR_SYSCALL:
         msg = "SSL_ERROR_SYSCALL";
         break;
      case SSL_ERROR_SSL:
         msg = "SSL_ERROR_SSL";
         break;
      default:
         msg = NULL;
   }

   if (msg)
      log_error_message(1, "SSL failure: ", msg, NULL);
   else
   {
      int dlen = digits_in_base(error, 10);
      char *buffer = (char*)alloca(dlen);
      itoa_buff(error, 10, buffer, dlen);

      log_error_message(1, "Unrecognized SSL_get_error() response, \"", msg, "\"",  NULL);
   }
}

int open_socket_talker(talker_user callback, const char *host_url, int host_port, void *data)
{
   struct addrinfo hints;
   struct addrinfo *ai_chain, *rp;

   int exit_value;
   int open_socket = -1, temp_socket = -1;

   int port_buffer_len = digits_in_base(host_port, 10) + 1;
   char *port_buffer = (char*)alloca(port_buffer_len);
   if (itoa_buff(host_port, 10, port_buffer, port_buffer_len))
   {
      memset((void*)&hints, 0, sizeof(struct addrinfo));
      hints.ai_family = AF_INET;
      hints.ai_socktype = SOCK_STREAM;
      hints.ai_flags = AI_CANONNAME;
      hints.ai_protocol = IPPROTO_TCP;

      exit_value = getaddrinfo(host_url, port_buffer, &hints, &ai_chain);

      if (exit_value==0)
      {
         rp = ai_chain;

         // Scan options until we successfully open a socket
         while (rp)
         {
            if ((rp->ai_family == PF_INET || rp->ai_family == PF_INET6)
                && rp->ai_socktype == SOCK_STREAM
                && rp->ai_protocol == IPPROTO_TCP)
            {
               temp_socket = socket(rp->ai_family,
                                    rp->ai_socktype,
                                    rp->ai_protocol);

               break;
            }

            rp = rp->ai_next;
         }

         // For an open socket, attempt to use it to connect
         if (temp_socket >= 0)
         {
            if (0 == connect(temp_socket, rp->ai_addr, rp->ai_addrlen))
               open_socket = temp_socket;
            else
               close(temp_socket);
         }

         // Clean up allocated memory
         freeaddrinfo(ai_chain);

         // If successfully connected with an open socket, construct
         // an STalker and use it to invoke the callback, closing the
         // socket upon the callback's return.
         if (open_socket >= 0)
         {
            STalker talker;
            memset(&talker, 0, sizeof(talker));
            init_sock_talker(&talker, open_socket);

            (*callback)(&talker, data);

            close(open_socket);
         }
      }
   }

   return exit_value;
}

/**
 * This function assumes that open_talker is a regular socket talker
 * because it will use the socket member to open SSL.
 */
void open_ssl_talker(talker_user callback, STalker *open_talker, void *data)
{
   const SSL_METHOD *method;
   SSL_CTX *context;
   SSL *ssl;
   int connect_outcome;

   assert(open_talker->socket_handle);

   OpenSSL_add_all_algorithms();
   /* err_load_bio_strings(); */
   ERR_load_crypto_strings();
   SSL_load_error_strings();

   /* openssl_config(null); */
   SSL_library_init();

   method = SSLv23_client_method();
   if (method)
   {
      context = SSL_CTX_new(method);

      if (context)
      {
         // following two not included in most recent example code i found.
         // it may be appropriate to uncomment these lines as i learn more.
         // ssl_ctx_set_verify(context, ssl_verify_peer, null);
         // ssl_ctx_set_verify_depth(context, 4);

         // we could set some flags, but i'm not doing it until i need to and i understand 'em
         // const long ctx_flags = ssl_op_no_sslv2 | ssl_op_no_sslv3 | ssl_op_no_compression;
         // ssl_ctx_set_options(context, ctx_flags);
         SSL_CTX_set_options(context, SSL_OP_NO_SSLv2);

         ssl = SSL_new(context);
         if (ssl)
         {
            SSL_set_fd(ssl, open_talker->socket_handle);

            connect_outcome = SSL_connect(ssl);

            if (connect_outcome == 1)
            {
               STalker ssl_talker;
               init_ssl_talker(&ssl_talker, ssl);

               (*callback)(&ssl_talker, data);
            }
            else if (connect_outcome == 0)
            {
               // failed with controlled shutdown
               log_ssl_error(ssl, connect_outcome);
            }
            else
            {
               log_ssl_error(ssl, connect_outcome);
            }

            SSL_free(ssl);
         }
         else
            log_error_message(1, "Failed to create a new SSL instance.", NULL);

         SSL_CTX_free(context);
      }
      else
         log_error_message(1, "Failed to initiate an SSL context.", NULL);
   }
   else
      log_error_message(1, "Failed to find SSL client method.", NULL);
}

/**
 * @brief Open a socket to the given host on the specified port.
 *
 * Unlike other functions in this library, this function **does not**
 * clean up after itself. A successfully calling this function must
 * explicitely close the socket handle.
 */
/* int get_connected_socket(const char *host_url, int port) */
/* { */
/*    struct addrinfo hints; */
/*    struct addrinfo *ai_chain, *rp; */

/*    int exit_value; */
/*    int open_socket = -1, temp_socket = -1; */

/*    int port_buffer_len = digits_in_base(port, 10) + 1; */
/*    char *port_buffer = (char*)alloca(port_buffer_len); */
/*    if (itoa_buff(port, 10, port_buffer, port_buffer_len)) */
/*    { */
/*       memset((void*)&hints, 0, sizeof(struct addrinfo)); */
/*       hints.ai_family = AF_INET; */
/*       hints.ai_socktype = SOCK_STREAM; */
/*       hints.ai_flags = AI_CANONNAME; */
/*       hints.ai_protocol = IPPROTO_TCP; */

/*       exit_value = getaddrinfo(host_url, port_buffer, &hints, &ai_chain); */

/*       if (exit_value==0) */
/*       { */
/*          rp = ai_chain; */
/*          while (rp) */
/*          { */
/*             if ((rp->ai_family == PF_INET || rp->ai_family == PF_INET6) */
/*                 && rp->ai_socktype == SOCK_STREAM */
/*                 && rp->ai_protocol == IPPROTO_TCP) */
/*             { */
/*                temp_socket = socket(rp->ai_family, */
/*                                     rp->ai_socktype, */
/*                                     rp->ai_protocol); */

/*                break; */
/*             } */

/*             rp = rp->ai_next; */
/*          } */

/*          if (temp_socket >= 0) */
/*          { */
/*             if (0 == connect(temp_socket, rp->ai_addr, rp->ai_addrlen)) */
/*                open_socket = temp_socket; */
/*             else */
/*                close(temp_socket); */
/*          } */

/*          freeaddrinfo(ai_chain); */
/*       } */
/*       else // exit_value != 0 getaddrinfo call failed */
/*       { */
/*          fprintf(stderr, */
/*                  "Failed to open socket for %s : %d: %s.\n", */
/*                  host_url, */
/*                  port, */
/*                  gai_strerror(exit_value)); */
/*       } */
/*    } */
/*    return open_socket; */
/* } */

/**
 * @brief Gets a SSL handle for an open socket, calling the MParcel::callback_func
 *        function pointer when it's SSL handle is working.
 *
 * This function automatically resends the EHLO request to update
 * the MParcel::SmtpCaps structure.  That ensures that the
 * talker_user function gets an accurate indication of the
 * server's capabilities.
 *
 * We have to reaquire the caps because one server, I think it
 * was mail.privateemail.com wouldn't allow STARTTLS when the
 * STARTTLS capability hadn't been advertised, so that meant
 * I couldn't simply check the use_tls flag and then call for
 * STARTTLS.  GMail seems to work similarly, though not identically.
 */
/* void open_ssl(ServerCreds *creds, int socket_handle, talker_user tu_callback, void *data) */
/* { */
/*    const SSL_METHOD *method; */
/*    SSL_CTX *context; */
/*    SSL *ssl; */
/*    int connect_outcome; */

/*    OpenSSL_add_all_algorithms(); */
/*    /\* err_load_bio_strings(); *\/ */
/*    ERR_load_crypto_strings(); */
/*    SSL_load_error_strings(); */

/*    /\* openssl_config(null); *\/ */
/*    SSL_library_init(); */

/*    method = SSLv23_client_method(); */
/*    if (method) */
/*    { */
/*       context = SSL_CTX_new(method); */

/*       if (context) */
/*       { */
/*          // following two not included in most recent example code i found. */
/*          // it may be appropriate to uncomment these lines as i learn more. */
/*          // ssl_ctx_set_verify(context, ssl_verify_peer, null); */
/*          // ssl_ctx_set_verify_depth(context, 4); */

/*          // we could set some flags, but i'm not doing it until i need to and i understand 'em */
/*          // const long ctx_flags = ssl_op_no_sslv2 | ssl_op_no_sslv3 | ssl_op_no_compression; */
/*          // ssl_ctx_set_options(context, ctx_flags); */
/*          SSL_CTX_set_options(context, SSL_OP_NO_SSLv2); */

/*          ssl = SSL_new(context); */
/*          if (ssl) */
/*          { */
/*             SSL_set_fd(ssl, socket_handle); */

/*             connect_outcome = SSL_connect(ssl); */

/*             if (connect_outcome == 1) */
/*             { */
/*                STalker *old_talker = parcel->stalker; */

/*                STalker talker; */
/*                init_ssl_talker(&talker, ssl); */
/*                parcel->stalker = &talker; */

/*                // Gmail advertises different capabilities after SSL initialization: */
/*                if (mcb_is_opening_smtp(parcel)) */
/*                   smtp_initialize_session(parcel); */

/*                (*tu_callback)(talker, data); */

/*                parcel->stalker = old_talker; */
/*             } */
/*             else if (connect_outcome == 0) */
/*             { */
/*                // failed with controlled shutdown */
/*                log_ssl_error(parcel, ssl, connect_outcome); */
/*                mcb_log_message(parcel, "ssl connection failed and was cleaned up.", NULL); */
/*             } */
/*             else */
/*             { */
/*                log_ssl_error(parcel, ssl, connect_outcome); */
/*                mcb_log_message(parcel, "ssl connection failed and aborted.", NULL); */
/*                mcb_log_message(parcel, "host: ", parcel->host_url, ", from: ", parcel->from, NULL); */
/*             } */

/*             SSL_free(ssl); */
/*          } */
/*          else */
/*             mcb_log_message(parcel, "Failed to create a new SSL instance.", NULL); */

/*          SSL_CTX_free(context); */
/*       } */
/*       else */
/*          mcb_log_message(parcel, "Failed to initiate an SSL context.", NULL); */
/*    } */
/*    else */
/*       mcb_log_message(parcel, "Failed to find SSL client method.", NULL); */
/* } */

/**
 * @brief Initialize connection with specified URL on specified port.
 *        Initializes TLS if requested.
 *
 * This function opens a socket, the opens SSL if requested.  In either
 * case, a STalker object is initialized and returned to the caller
 * through the MParcel pointer.
 */
/* void prepare_talker(ServerCreds *creds, talker_user tu_callback, void *data) */
/* { */
/*    const char *host = creds->host_url; */
/*    int         port = creds->host_port; */

/*    char        buffer[1024]; */
/*    int         bytes_read; */
/*    int         socket_response; */
/*    int         smtp_mode_socket = 0; */

/*    int osocket = get_connected_socket(host, port); */
/*    if (osocket > 0) */
/*    { */
/*       STalker talker; */
/*       init_sock_talker(&talker, osocket); */
/*       parcel->stalker = &talker; */

/*       if (mcb_is_opening_smtp(parcel)) */
/*       { */
/*          bytes_read = mcb_recv_data(parcel, buffer, sizeof(buffer)); */
/*          socket_response = atoi(buffer); */
/*          if (socket_response >= 200 && socket_response < 300) */
/*          { */
/*             smtp_mode_socket = 1; */
/*             smtp_initialize_session(parcel); */
/*          } */
/*       } */

/*       if (parcel->starttls) */
/*       { */
/*          // For SMTP using TLS, we must explicitly start tls */
/*          if (smtp_mode_socket && parcel->caps.cap_starttls) */
/*          { */
/*             mcb_advise_message(parcel, "Starting TLS", NULL); */

/*             mcb_send_data(parcel, "STARTTLS", NULL); */
/*             bytes_read = mcb_recv_data(parcel, buffer, sizeof(buffer)); */
/*             if (bytes_read > 3) */
/*             { */
/*                socket_response = atoi(buffer); */
/*                if (socket_response >= 200 && socket_response < 300) */
/*                { */
/*                   // For GMail, at least, the capabilities have changed, */
/*                   // so we'll reaquire them now. */
/*                   /\* smtp_initialize_session(parcel); *\/ */

/*                   open_ssl(parcel, osocket, talker_user); */
/*                } */
/*                else */
/*                { */
/*                   buffer[bytes_read] = '\0'; */
/*                   mcb_log_message(parcel, "STARTTLS failed (", buffer, ")", NULL); */
/*                } */
/*             } */
/*             else */
/*                mcb_log_message(parcel, "Corrupt response to STARTTLS.", NULL); */
/*          } */
/*          else // Non-SMTP (ie POP) using TLS: */
/*             open_ssl(parcel, osocket, talker_user); */
/*       } */
/*       else // Not using TLS */
/*          (*talker_user)(parcel); */

/*       close(osocket); */
/*    } */
/* } */

#ifdef SOCKET_MAIN

#include "socktalk.c"
#include "logging.c"

void use_the_talker(STalker *talker, void *data)
{
   char buffer[1024];

   stk_send_line(talker, "EHLO ", NULL);
   stk_recv_line(talker, buffer, sizeof(buffer));

   printf("Result of EHLO is [34;1m%s[m\n", buffer);
}

int main(int argc, const char **argv)
{
   const char *host_url = "smtp.gmail.com";
   int host_port = 587;
   
   int exit_code = open_socket_talker(use_the_talker, host_url, host_port, NULL);
   if (exit_code)
   {
      fprintf(stderr,
              "Failed to open socket for %s:%d: (%d) %s.\n",
              host_url,
              host_port,
              exit_code,
              gai_strerror(exit_code));
   }   
}

#endif


/* Local Variables: */
/* compile-command: "base=socket; gcc -Wall -Werror -ggdb -DSOCKET_MAIN -DDEBUG  -o $base ${base}.c -lssl -lcrypto" */
/* End: */
