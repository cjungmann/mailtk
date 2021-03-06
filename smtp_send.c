// -*- compile-command: "base=smtp_send; gcc -Wall -Werror -ggdb -DDEBUG -o $base ${base}.c -Wl,-R,. libmailtk.so" -*-

#include "mailtk.h"

#include "dbg_test.c"

typedef struct _smtp_email_sack
{
   ServerCreds sc;
   SMTPCaps    scaps;
   STalker     *stalker;
   LineDrop    *linedrop;
} EmailSack;

typedef struct _my_data
{
   BaseCreds base_creds;
   const char *account;
   const char *login;
   const char *password;
} MyData;

#include "sample_creds.c"

/**
 * Custom dropper_break_check() function that will detect
 * the end of an email.  We don't want to use the default
 * dropper_break_check() function because an email may
 * reasonably include an empty line that triggers the
 * default function to signal a break.
 */
int email_termination_test(const LineDrop *ld)
{
   const char *line;
   int line_len;
   DropGetLine(ld, &line, &line_len);

   char record_separator = '\x1E';  // RS, dec=30 or Ctrl-^

   return line_len == 1 && *line == record_separator;
}

void send_email(void *emailsack)
{
   EmailSack *es = (EmailSack*)emailsack;

   LineDrop *ld = es->linedrop;
   const char *line;
   int line_len;

   // Replace break_check to stop breaking on empty lines
   // and start breaking on a new character the marks the
   // end of the email
   dropper_break_check old_checker = ld->break_check;
   ld->break_check = email_termination_test;

   STalker stdout_talker;
   STalker *old_talker = NULL;
   int write_to_stdout = 0;

   if (write_to_stdout)
   {
      init_stdout_talker(&stdout_talker);
      old_talker = es->stalker;
      es->stalker = &stdout_talker;
   }

   do
   {
      DropGetLine(ld, &line, &line_len);
      stk_simple_send_line(es->stalker, line, line_len);
   } while (DropAdvance(ld));

   if (write_to_stdout)
      es->stalker = old_talker;

   ld->break_check = old_checker;
}


void send_preamble(RecipLink *rchain, void *data)
{
   EmailSack *es = (EmailSack*)data;
   char buffer[1024];  // for reading response to DATA line
   int reply_status, bytes_received;

   // Count is the number of email addresses accepted by
   // the SMTP server.  There is no point in continuing
   // if none were accepted.
   int count = smtp_send_envelope(es->stalker,
                                  es->sc.account,
                                  rchain);

   dump_recip_list(rchain);

   if (count)
   {
      stk_simple_send_line(es->stalker, "DATA", 4);
      bytes_received = stk_recv_line(es->stalker, buffer, sizeof(buffer));
      reply_status = atoi(buffer);

      if (reply_status >=300 && reply_status < 400)
      {
         LineDrop *ld = es->linedrop;
         // Advance past recipients break line
         if (DropAdvance(ld))
         {
            smtp_send_headers(es->linedrop, es->stalker, rchain);

            // Advance past headers break line
            if (DropAdvance(ld))
            {
               send_email(es);

               stk_send_line(es->stalker, ".", NULL);
               stk_send_line(es->stalker, NULL);

               bytes_received = stk_recv_line(es->stalker, buffer, sizeof(buffer));
               buffer[bytes_received] = '\0';

               reply_status = atoi(buffer);
               fprintf(stderr,
                       "Result of sending email is %d, [33;1m%s[m\n",
                       reply_status,
                       buffer);
               
            }
         }
      }
      else
         fprintf(stderr,
                 "DATA message returned an error (%d): [33;1m%s[m.\n",
                 reply_status,
                 buffer);
   }
   else
      printf("The SMTP server is not prepared to accept any addresses.\n");
}

void process_emails(STalker *stalker, void *emailsack)
{
   // Save settled-on stalker object to the EmailSack object:
   EmailSack *es = (EmailSack*)emailsack;
   es->stalker = stalker;

   build_recip_chain(send_preamble, es->linedrop, emailsack);
}

void smtp_tls_stalker_user(STalker *stalker, void *emailsack)
{
   EmailSack *es = (EmailSack*)emailsack;
   ServerCreds *sc = &es->sc;

   SMTPError serror;
   if (greet_smtp_server(sc->host_url, stalker, &es->scaps))
   {
      if (cget_auth_login(&es->scaps))
      {
         serror = authorize_with_login(sc->login, sc->password, stalker);
         if (serror)
            printf("Authorization failed with %d.\n", serror);
         else
            process_emails(stalker, emailsack);
      }
   }
}

void smtp_stalker_user(STalker *stalker, void *emailsack)
{
   EmailSack *es = (EmailSack*)emailsack;
   const char *host_url = es->sc.host_url;

   if (greet_smtp_server(host_url, stalker, &es->scaps))
   {
      if (cget_starttls(&es->scaps))
         start_tls(stalker, emailsack, smtp_tls_stalker_user);
      else
         process_emails(stalker, emailsack);
   }
}



const char *email_job_array[] = {
   "recipient@gmail.com",
   "+target@gmail.com",
   "-spy@gmail.com",
   "#test@gmail.com",
   "",
   "Subject: Testing",
   "",
   "This is the text of a sample email.",
   "It is short and boring, so it might end up",
   "tagged as spam and discarded.",
   "",
   "I hope not",
   NULL
};

FILE* open_cli_file(const char *filepath)
{
   FILE *rval = fopen(filepath, "r");
   if (!rval)
      printf("There was an error attempting to open [33;1m%s[m (%s).\n", filepath, strerror(errno));

   return rval;
}


int main(int argc, const char **argv)
{
   MyData data;
   init_my_data(&data);

   printf("Showing BaseCreds values: URL=[32;1m%s[m, port=[32;1m%d[m\n",
          ((BaseCreds*)&data)->host_url,
          ((BaseCreds*)&data)->host_port);

   return 0;
          

   EmailSack es;
   memset(&es, 0, sizeof(EmailSack));

   LineDrop ld;
   es.linedrop = &ld;

   // Read, then extract ServerCreds values for opening the socket:
   init_server_creds(&es.sc);
   const char *host_url = es.sc.host_url;
   int        host_port = es.sc.host_port;

   int exit_code = 0;

   if (argc > 1)
   {
      FILE *strfile;
      if ((strfile = open_cli_file(argv[1])))
      {
         StreamLineDropper sld;
         char buffer[1024];
         stream_init_dropper(&sld, strfile, buffer, sizeof(buffer));
         init_stream_line_drop(&ld, &sld);

         exit_code = open_socket_talker(host_url, host_port, &es, smtp_stalker_user);

         fclose(strfile);
      }
   }
   else
   {
      ListLineDropper lld;
      list_init_dropper(&lld, email_job_array);
      init_list_line_drop(&ld, &lld);

      exit_code = open_socket_talker(host_url, host_port, &es, smtp_stalker_user);
   }

   if (exit_code)
   {
      printf("Error running open_socket_talker (%d)\n", exit_code);
   }

   return 0;
}
