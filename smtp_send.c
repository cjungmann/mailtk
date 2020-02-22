// -*- compile-command: "base=smtp_send; gcc -Wall -Werror -ggdb -DDEBUG -o $base ${base}.c -Wl,-R,. libmailtk.so" -*-

#include "mailtk.h"
#include "sample_creds.c"

#include "dbg_test.c"

typedef struct _smtp_email_sack
{
   ServerCreds sc;
   SMTPCaps    scaps;
   STalker     *stalker;
   LineDrop    *linedrop;
} EmailSack;

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

   do
   {
      DropGetLine(ld, &line, &line_len);
      stk_simple_send_line(es->stalker, line, line_len);
   } while (DropAdvance(ld));

   ld->break_check = old_checker;
}


void send_preamble(RecipLink *rchain, void *data)
{
   EmailSack *es = (EmailSack*)data;

   int count = smtp_send_envelope(es->stalker,
                                  es->sc.account,
                                  rchain);

   dump_recip_list(rchain);

   // Disable continuation 
   count = 0;

   if (count)
   {
      stk_simple_send_line(es->stalker, "DATA", 4);

      smtp_send_headers(es->linedrop, es->stalker, rchain);

      // send a newline after all the headers have been sent:
      stk_simple_send_line(es->stalker, "", 0);
      
      send_email(es);
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
   if (greet_smtp_server(&es->scaps, sc->host_url, stalker))
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

   if (greet_smtp_server(&es->scaps, host_url, stalker))
   {
      if (cget_starttls(&es->scaps))
         start_tls(smtp_tls_stalker_user, stalker, emailsack);
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

         exit_code = open_socket_talker(smtp_stalker_user, host_url, host_port, &es);

         fclose(strfile);
      }
   }
   else
   {
      ListLineDropper lld;
      list_init_dropper(&lld, email_job_array);
      init_list_line_drop(&ld, &lld);

      exit_code = open_socket_talker(smtp_stalker_user, host_url, host_port, &es);
   }

   if (exit_code)
   {
      printf("Error running open_socket_talker (%d)\n", exit_code);
   }

   return 0;
}
