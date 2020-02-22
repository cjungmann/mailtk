// -*- compile-command: "base=smtp_iact; gcc -Wall -Werror -ggdb -DSMTP_IACT_MAIN -DDEBUG -o $base ${base}.c -Wl,-L,. -lmailtk" -*-

#include "smtp_iact.h"
#include <alloca.h>
#include <string.h>
#include <assert.h>

void set_link_type(RecipLink *link, const char *address)
{
   switch(*address)
   {
      case '+':
         link->rtype = RT_CC;
         break;
      case '-':
         link->rtype = RT_BCC;
         break;
      case '#':
         link->rtype = RT_BCC;
         break;
   }
}

void build_recip_chain(RecipChainUser callback, LineDrop *ld, void *data)
{
   RecipLink *head_link = NULL, *tail_link = NULL, *cur_link;

   const char *line;
   int line_len;

   char *temp_address;

   do
   {
      DropGetLine(ld, &line, &line_len);

      if (line_len > 0)
      {
         cur_link = (RecipLink*)alloca(sizeof(RecipLink));
         memset(cur_link, 0, sizeof(RecipLink));

         set_link_type(cur_link, line);

         if (strchr("+-#", *line))
         {
            ++line;
            --line_len;
         }

         temp_address = (char*)alloca(line_len+1);
         memcpy(temp_address, line, line_len);
         temp_address[line_len] = '\0';

         cur_link->address = temp_address;

         if (tail_link)
         {
            tail_link->next = cur_link;
            tail_link = cur_link;
         }
         else
            head_link = tail_link = cur_link;
      }

   } while (DropAdvance(ld));

   (*callback)(head_link, data);
}

int count_unignored_recips(const RecipLink *chain)
{
   int count = 0;
   while (chain)
   {
      if (chain->rtype != RT_IGNORE)
         ++count;
      chain = chain->next;
   }

   return count;
}

int smtp_send_envelope(STalker *stalker, const char *from, RecipLink *recipient_chain)
{
   char buffer[1024];

   // Catch programming error, not a STalker object along with data
   // object passed along through build_recip_chain(), etc:
   assert(stalker);

   int bytes_read;
   int reply_status;
   int recipients_accepted = 0;

   stk_send_line(stalker, "MAIL FROM: <", from , ">", NULL);
   bytes_read = stk_recv_line(stalker, buffer, sizeof(buffer));
   buffer[bytes_read] = '\0';

   reply_status = atoi(buffer);
   if (reply_status > 200 && reply_status < 300)
   {
      RecipLink *rptr = recipient_chain;
      while (rptr)
      {
         if (rptr->rtype != RT_IGNORE)
         {
            stk_send_line(stalker, "RCPT TO: <", rptr->address, ">", NULL);
            bytes_read = stk_recv_line(stalker, buffer, sizeof(buffer));
            buffer[bytes_read] = '\0';

            rptr->smtp_status = reply_status = atoi(buffer);

            if (reply_status >= 200 && reply_status < 300)
               ++recipients_accepted;
         }
         rptr = rptr->next;
      }
   }

   return recipients_accepted;
}

int smtp_recipient_accepted(const RecipLink *rchain)
{
   return rchain->smtp_status >= 200 && rchain->smtp_status < 300;
}

int smtp_count_recipients_by_type(const RecipLink *rchain, RecipType rtype)
{
   int count = 0;
   while (rchain)
   {
      if (rchain->rtype == rtype && smtp_recipient_accepted(rchain))
         ++count;

      rchain = rchain->next;
   }

   return count;
}

void smtp_send_recipient_headers_by_type(STalker *stalker, RecipLink *rchain, RecipType rtype)
{
   int type_count = smtp_count_recipients_by_type(rchain, rtype);
   int sent_count = 0;

   if (type_count > 0)
   {
      switch(rtype)
      {
         case RT_TO:
            stk_simple_send_unlined(stalker, "To: ", 4);
            break;
         case RT_CC:
            stk_simple_send_unlined(stalker, "Cc: ", 4);
            break;
         case RT_BCC:
            stk_simple_send_unlined(stalker, "Bcc: ", 5);
            break;
         default:
            // Defeat the loop with a NULL:
            rchain = NULL;
            break;
      }

      while (rchain)
      {
         if (rchain->rtype == rtype && smtp_recipient_accepted(rchain))
         {
            if (sent_count > 0)
               stk_simple_send_unlined(stalker, ", ", 2);

            stk_simple_send_unlined(stalker, rchain->address, strlen(rchain->address));
         }
         rchain = rchain->next;
      }

      // send a newline after all the unlined addresses:
      stk_simple_send_line(stalker, "", 0);
   }
}

/**
 * Transmit headers from LineDrop until the break, then
 * transmit to:, cc:, and bcc addresses as headers.
 */
void smtp_send_headers(LineDrop *ld, STalker *stalker, RecipLink *rchain)
{
   const char *line;
   int line_len;

   // Send recipient headers:
   smtp_send_recipient_headers_by_type(stalker, rchain, RT_TO);
   smtp_send_recipient_headers_by_type(stalker, rchain, RT_CC);
   smtp_send_recipient_headers_by_type(stalker, rchain, RT_BCC);

   // Sending remaining headers
   do
   {
      DropGetLine(ld, &line, &line_len);
      stk_simple_send_line(stalker, line, line_len);
   } while (DropAdvance(ld));
}



#ifdef SMTP_IACT_MAIN

#include "linedrop.c"

/**
 * Callback function for test_build_recip_chain()
 */
void use_recip_chain(RecipLink *chain, void *data)
{
   printf("Got a recipient chain.\n");
   printf("Scan the list of recipients to check for missing or extra characters.\n");
   printf("Key: [7m TO [27;30m [7;32m CC [27m [7;34m BCC [27m [7;31m IGNORE [m\n");

   RecipLink *ptr = chain;
   while (ptr)
   {
      switch(ptr->rtype)
      {
         case RT_TO:
            // Using fputs to avoid the automatic newline
            fputs("[7m", stdout);
            break;
         case RT_CC:
            fputs("[7;32m", stdout);
            break;
         case RT_BCC:
            fputs("[7;34m", stdout);
            break;
         case RT_IGNORE:
            fputs("[7;31m", stdout);
            break;
      }

      printf("%s", ptr->address);
      puts("[m");

      ptr = ptr->next;
   }
}

/**
 * Simple test to build a recipient chain from a list of email addresses.
 */
void test_build_recip_chain(void)
{
   const char *list[] = {
      "recipient@gmail.com",
      "+target@gmail.com",
      "-spy@gmail.com",
      "#test@gmail.com",
      NULL
   };

   ListLineDropper lld;
   LineDrop ld;
   list_init_dropper(&lld, list);
   init_list_line_drop(&ld, &lld);

   build_recip_chain(use_recip_chain, &ld, NULL);
}


int main(int argc, const char **argv)
{
   test_build_recip_chain();

   return 0;
}

#endif
