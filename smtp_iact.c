// -*- compile-command: "base=smtp_iact; gcc -Wall -Werror -ggdb -DSMTP_IACT_MAIN -U NDEBUG -o $base ${base}.c" -*-

#include "smtp_iact.h"
#include <alloca.h>
#include <string.h>

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

void build_recip_chain(LineDrop *ld, void *data, RecipChainUser callback)
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


#ifdef SMTP_IACT_MAIN

#include "linedrop.c"

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
         case RT_TO: fputs("[7m", stdout); break;
         case RT_CC: fputs("[7;32m", stdout); break;
         case RT_BCC: fputs("[7;34m", stdout); break;
         case RT_IGNORE: fputs("[7;31m", stdout); break;
      }
      printf("%s", ptr->address);
      puts("[m");

      ptr = ptr->next;
   }
}

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

   build_recip_chain(&ld, NULL, use_recip_chain);
}


int main(int argc, const char **argv)
{
   test_build_recip_chain();

   return 0;
}

#endif
