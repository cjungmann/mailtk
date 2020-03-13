// -*- compile-command: "base=test; gcc -Wall -Werror -ggdb -DDEBUG -o $base ${base}.c -lcode64 -Wl,-R,. libmailtk.so" -*-

#include "mailtk.h"
#include <stdio.h>
#include <code64.h>

/*******************************
 * Definitions and Prototypes
 * Future header file contents.
 ******************************/

// Generic Login Section
typedef int (*login_check)(STalker *talker, void *data);

typedef struct _mtk_login_object
{
   login_check checker;
   void        *data;
} LoggerIn;

int mtk_login(STalker *talker, LoggerIn *li) { return (*li->checker)(talker, li->data); }

// Generic Connection Section

typedef enum _mtk_mail_type { MT_NONE=0, MT_SMTP, MT_POP } MType;

typedef void (*mtk_talker_user)(STalker *talker, void *data);

typedef struct _mtk_socket_spec
{
   const char *host_url;
   int         host_port;
   int         use_ssl;
   MType       mail_type;
   LoggerIn    *loggerin;
} SocketSpec;

const char *mtk_mail_type_str(MType mt);
void mtk_display_socket_spec(const SocketSpec *spec, FILE *str);
int mtk_create_connection(SocketSpec *ss, mtk_talker_user callback);
int mtk_send_credentials(STalker *talker, SocketSpec *ss);

int mtk_is_smtp(const SocketSpec *ss) { return ss->mail_type == MT_SMTP; }
int mtk_is_pop(const SocketSpec *ss)  { return ss->mail_type == MT_POP; }

int mtk_auth_login(STalker *talker, const char *login, const char *password);
int mtk_auth_plain(STalker *talker, const char *login, const char *password);


/***************************
 * Internal prototypes, etc.
 **************************/


typedef struct _talker_callback_params
{
   mtk_talker_user callback;
   void            *data;
} TCParams;

void invoke_callback(STalker *talker, TCParams *tcp)
{
   (*tcp->callback)(talker, tcp->data);
}


// Implementations


int mtk_auth_login(STalker *talker, const char *login, const char *password)
{
   printf("Attempting to authorize with LOGIN protocol, with %s : %s.\n", login, password);

   int len_login = strlen(login);
   int len_password = strlen(password);
   int len_longest = len_login > len_password ? len_login : len_password;
   int len_output = c64_encode_chars_needed(len_longest);
   char *output = (char*)alloca(len_output);

   char recv_buffer[256];
   int recv_status;

   stk_send_line(talker, "AUTH LOGIN ", NULL);
   stk_recv_line(talker, recv_buffer, sizeof(recv_buffer));
   recv_status = atoi(recv_buffer);
   if (recv_status == 334)
   {
      c64_encode_to_buffer(login, len_login, (uint32_t*)output, len_output);
      stk_send_line(talker, output, NULL);
      stk_recv_line(talker, recv_buffer, sizeof(recv_buffer));
      recv_status = atoi(recv_buffer);
      if (recv_status == 334)
      {
         c64_encode_to_buffer(password, len_password, (uint32_t*)output, len_output);
         stk_send_line(talker, output, NULL);
         stk_recv_line(talker, recv_buffer, sizeof(recv_buffer));
         recv_status = atoi(recv_buffer);
         return recv_status == 235;
      }
   }

   return 0;
}

int mtk_auth_plain(STalker *talker, const char *login, const char *password)
{
   printf("Attempting to authorize with PLAIN protocol, with %s : %s.\n", login, password);

   int len_login = strlen(login);
   int len_password = strlen(password);
   int len_together = len_login + len_password + 2;
   int len_coded = c64_encode_chars_needed(len_together);

   char *source_str = (char*)alloca(len_together);
   char *coded_str = (char*)alloca(len_coded);
   char recv_buffer[256];
   int recv_status;

   char *ptr;
   memcpy(source_str, login, len_login);
   ptr = source_str + len_login;
   *ptr++ = '\0';
   memcpy(ptr, password, len_password);
   ptr += len_password;
   *ptr++ = '\0';

   c64_encode_to_buffer(source_str, len_together, (uint32_t*)coded_str, len_coded);

   stk_send_line(talker, "AUTH PLAIN ", coded_str, NULL);
   stk_recv_line(talker, recv_buffer, sizeof(recv_buffer));
   recv_status = atoi(recv_buffer);

   return recv_status == 235;
}


const char *mtk_mail_type_str(MType mt)
{
   switch (mt)
   {
      case MT_NONE: return "None";
      case MT_SMTP: return "SMTP";
      case MT_POP: return "POP";
      default: return "Unknown";
   }
}

void mtk_display_socket_spec(const SocketSpec *spec, FILE *filestr)
{
   if (filestr == NULL)
      filestr = stderr;

   fprintf(filestr, "Host URL:  [32;1m%s[m\n", spec->host_url);
   fprintf(filestr, "Host port: [32;1m%d[m\n", spec->host_port);
   fprintf(filestr, "Using SSL: [32;1m%s[m\n", spec->use_ssl ? "Yes" : "No");
   fprintf(filestr, "Mail Type: [32;1m%s[m\n", mtk_mail_type_str(spec->mail_type));
}

int mtk_send_credentials(STalker *talker, SocketSpec *ss)
{
   if (ss->loggerin)
      return mtk_login(talker, ss->loggerin);
   else
      return 1;   // pretend login was successful
}

void mtk_internal_pre_return_talker(STalker *talker, void *data)
{
   TCParams *tcp = (TCParams*)data;
   SocketSpec *ss = (SocketSpec*)tcp->data;

   if (ss->loggerin)
   {
      if (!mtk_login(talker, ss->loggerin))
      {
         printf("Ya failed to login, yo.\n");
         return;
      }
   }

   invoke_callback(talker, tcp);
}

void mtk_internal_receive_ssl_talker(STalker *talker, void *data)
{
   printf("Got the SSL socket.\n");

   TCParams *tcp = (TCParams*)data;
   SocketSpec *ss = (SocketSpec*)tcp->data;

   if (mtk_send_credentials(talker, ss))
      printf("Authorized access.\n");
   else
      printf("Failed to secure access.\n");
}

void mtk_internal_receive_socket_talker(STalker *talker, void *data)
{
   TCParams *tcp = (TCParams*)data;
   SocketSpec *ss = (SocketSpec*)tcp->data;
   char buffer[1024];
   int bytes_received;

   // Read SMTP server greeting
   if (mtk_is_smtp(ss))
      bytes_received = stk_recv_line(talker, buffer, sizeof(buffer));

   if (ss->use_ssl)
   {
      if (mtk_is_smtp(ss))
      {
         stk_send_line(talker, "EHLO ", ss->host_url, NULL);
         bytes_received = stk_recv_line(talker, buffer, sizeof(buffer));
         if (bytes_received < 3)
            return;

         stk_send_line(talker, "STARTTLS", NULL);
         bytes_received = stk_recv_line(talker, buffer, sizeof(buffer));
         if (bytes_received < 3)
            return;
      }
      open_ssl_talker(talker, data, mtk_internal_pre_return_talker);
   }
   else
      mtk_internal_pre_return_talker(talker, tcp);
}

int mtk_create_connection(SocketSpec *ss, mtk_talker_user callback)
{
   TCParams tcp = { callback, ss };

   return open_socket_talker(ss->host_url,
                             ss->host_port,
                             &tcp,
                             mtk_internal_receive_socket_talker);
}



/* void mtk_internal_smtp_ssl_user(STalker *talker, void *TalkerCallbackPayload) */
/* { */
/* } */

/* void mtk_internal_smtp_socket_user(STalker *talker, void *TalkerCallbackPayload) */
/* { */
/*    mtk_TCP *tcp = (mtk_TCP*)TalkerCallbackPayload; */
   
/*    ConnectionInfo *ci = tcp->ci; */
   
/*    if (greet_smtp_server(ci->host_url, talker, &ci->scaps)) */
/*    { */
/*       (*tcp->ultimate_callback)(talker, tcp); */
/*    } */
/* } */


/* void mtk_prepare_smtp_talker(ConnectionInfo *ci, mtk_talker_user callback) */
/* { */
/*    TalkerCallbackPayload tcp = { callback, ci }; */
/*    open_socket_talker(ci->host_url, ci->host_port, ci, mtk_internal_smtp_socket_user); */
/* } */

/* int mtk_create_connection(SocketSpec *ss, mtk_talker_user callback) */
/* { */
/* } */



// End-product code, that is code that uses the above code
// as if it were a library.

typedef struct _my_socket_spec
{
   SocketSpec ss;
   const char *login;
   const char *password;
} MySocketSpec;

void display_my_socket_spec(const MySocketSpec *mss, FILE *filestr)
{
   if (filestr == NULL)
      filestr = stderr;

   mtk_display_socket_spec(&mss->ss, filestr);

   fprintf(filestr, "login:    [32;1m%s[m.\n", mss->login);
   fprintf(filestr, "password: [32;1m%s[m.\n", mss->password);

}



/***********************************
 * Command line processing functions
 **********************************/

typedef void (*OptionSetter)(void *option, const char *str);

void int_setter(void *option, const char *str)
{
   *(int*)option = atoi(str);
}

void str_setter(void *option, const char *str)
{
   *(const char**)option = str;
}

void flag_setter(void *option, const char *str)
{
   *(int*)option = 1;
}

void mail_type_setter(void *option, const char *str)
{
   switch(*str)
   {
      case 's':
      case 'S':
         *(MType*)option = MT_SMTP;
         break;
      case 'p':
      case 'P':
         *(MType*)option = MT_POP;
         break;
      default:
         *(MType*)option = MT_NONE;
         break;
   };
}

void prepare_socket_spec_from_CL(MySocketSpec *ss, int argc, const char **argv)
{
   const char **end = &argv[argc];
   const char **ptr = argv + 1;
   const char *opt;

   void         *option_to_set = NULL;
   OptionSetter option_setter = NULL;

   while (ptr < end)
   {
      if (option_setter)
      {
         (*option_setter)(option_to_set, *ptr);
         option_to_set = NULL;
         option_setter = NULL;
      }
      else if (**ptr == '-')
      {
         opt = (*ptr)+1;
         while (*opt)
         {
            switch(*opt)
            {
               case 'l':    // login
                  option_to_set = (void*)&ss->login;
                  option_setter = str_setter;
                  goto option_break;

               case 'w':    // w
                  option_to_set = (void*)&ss->password;
                  option_setter = str_setter;
                  goto option_break;
                  
               case 'u':    // url
                  option_to_set = (void*)&ss->ss.host_url;
                  option_setter = str_setter;
                  goto option_break;

               case 'p':   // port
                  option_to_set = (void*)&ss->ss.host_port;
                  option_setter = int_setter;
                  goto option_break;

               case 's':   // use ssl
                  ss->ss.use_ssl = 1;
                  break;

               case 't':   // email interaction type (smtp / pop)
                  option_to_set = (void*)&ss->ss.mail_type;
                  option_setter = mail_type_setter;
            }

            ++opt;
         }

        option_break: ;
      }

      ++ptr;
   }
}

void mtk_use_talker(STalker *talker, void *data)
{
   MySocketSpec *mss = (MySocketSpec*)data;
   const char *login = mss->login;
   const char *password = mss->password;

   /* if (mtk_auth_login(talker, login, password)) */
   if (mtk_auth_plain(talker, login, password))
      printf("Ready to send some emails!\n");
   else
      printf("Failed to authorize.\n");
}



// End of command line processing functions

int main(int argc, const char **argv)
{
   MySocketSpec mss;
   memset(&mss, 0, sizeof(mss));

   prepare_socket_spec_from_CL(&mss, argc, argv);

   display_my_socket_spec(&mss, NULL);

   mtk_create_connection(&mss.ss, mtk_use_talker);

   
   return 0;
}
