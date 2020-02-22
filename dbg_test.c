/**
 * This source file contains some functions that can be
 * used to help with debugging **mailtk** development.
 *
 * The functions should probably not be included in the
 * library as they are meant to be mainly useful when
 * developing apps that use the library.
 */

const char *get_recip_class(const RecipLink *rchain)
{
   static const char s_to[] = "To:";
   static const char s_cc[] = "Cc:";
   static const char s_bcc[] = "Bcc:";
   static const char s_ignore[] = "ignored";
   static const char s_unknown[] = "unknown";
   switch(rchain->rtype)
   {
      case RT_TO:
         return s_to;
      case RT_CC:
         return s_cc;
      case RT_BCC:
         return s_bcc;
      case RT_IGNORE:
         return s_ignore;
      default:
         return s_unknown;
   }
}

void dump_recip_list(const RecipLink *rchain)
{
   printf("%7s %80s %10s.\n", "class", "email address", "smtp_reply");
   while (rchain)
   {
      printf("%7s %80s %10d\n",
             get_recip_class(rchain),
             rchain->address,
             rchain->smtp_status);
      
      rchain = rchain->next;
   }
}
