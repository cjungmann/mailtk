// -*- compile-command: "base=smtp_setcaps; gcc -Wall -Werror -ggdb -DSMTP_SETCAPS_MAIN -U NDEBUG -o $base ${base}.c" -*-

#include <stddef.h>    // for NULL value
#include <stdio.h>     // for printf() in show_smtp_caps()
#include <stdlib.h>    // for atoi()
#include <string.h>    // for strncmp()
#include <ctype.h>     // for isdigit()

#include <assert.h>

#include "smtp_setcaps.h"
#include "logging.h"

void cset_starttls(SMTPCaps *caps,
                   const char *line,
                   int line_len)                   { caps->cap_starttls = 1; }
int cget_starttls(const SMTPCaps *caps)            { return caps->cap_starttls == 1; }

void cset_chunking(SMTPCaps *caps,
                   const char *line,
                   int line_len)                   { caps->cap_chunking = 1; }
int cget_chunking(const SMTPCaps *caps)            { return caps->cap_chunking == 1; }

void cset_enhancedstatuscodes(SMTPCaps *caps,
                              const char *line,
                              int line_len)        { caps->cap_enhancedstatuscodes = 1; }
int cget_enhancedstatuscodes(const SMTPCaps *caps) { return caps->cap_enhancedstatuscodes == 1; }

void cset_8bitmime(SMTPCaps *caps,
                   const char *line,
                   int line_len)                   { caps->cap_8bitmime = 1; }
int cget_8bitmime(const SMTPCaps *caps)            { return caps->cap_8bitmime == 1; }

void cset_7bitmime(SMTPCaps *caps,
                   const char *line,
                   int line_len)                   { caps->cap_7bitmime = 1; }
int cget_7bitmime(const SMTPCaps *caps)            { return caps->cap_7bitmime == 1; }

void cset_pipelining(SMTPCaps *caps,
                     const char *line,
                     int line_len)                 { caps->cap_pipelining = 1; }
int cget_pipelining(const SMTPCaps *caps)          { return caps->cap_pipelining == 1; }

void cset_smtputf8(SMTPCaps *caps,
                   const char *line,
                   int line_len)                   { caps->cap_smtputf8 = 1; }
int cget_smtputf8(const SMTPCaps *caps)            { return caps->cap_smtputf8 == 1; }

void cset_auth_plain(SMTPCaps *caps,
                     const char *line,
                     int line_len)                 { caps->cap_auth_plain = 1; }
int cget_auth_plain(const SMTPCaps *caps)          { return caps->cap_auth_plain == 1; }

void cset_auth_plain_clienttoken(SMTPCaps *caps,
                                 const char *line,
                                 int line_len)     { caps->cap_auth_plain_clienttoken = 1; }
int cget_auth_plain_clienttoken(SMTPCaps *caps)    { return caps->cap_auth_plain_clienttoken == 1; }

void cset_auth_login(SMTPCaps *caps,
                     const char *line,
                     int line_len)                 { caps->cap_auth_login = 1; }
int cget_auth_login(const SMTPCaps *caps)          { return caps->cap_auth_login == 1; }

void cset_auth_gssapi(SMTPCaps *caps,
                      const char *line,
                      int line_len)                { caps->cap_auth_gssapi = 1; }
int cget_auth_gssapi(const SMTPCaps *caps)         { return caps->cap_auth_gssapi == 1; }

void cset_auth_digest_md5(SMTPCaps *caps,
                          const char *line,
                          int line_len)            { caps->cap_auth_digest_md5 = 1; }
int cget_auth_digest_md5(const SMTPCaps *caps)     { return caps->cap_auth_digest_md5 == 1; }

void cset_auth_md5(SMTPCaps *caps,
                   const char *line,
                   int line_len)                   { caps->cap_auth_md5 = 1; }
int cget_auth_md5(const SMTPCaps *caps)            { return caps->cap_auth_md5 == 1; }

void cset_auth_cram_md5(SMTPCaps *caps,
                        const char *line,
                        int line_len)              { caps->cap_auth_cram_md5 = 1; }
int cget_auth_cram_md5(const SMTPCaps *caps)       { return caps->cap_auth_cram_md5 == 1; }

void cset_auth_oauth10a(SMTPCaps *caps,
                        const char *line,
                        int line_len)              { caps->cap_auth_oauth10a = 1; }
int cget_auth_oauth10a(const SMTPCaps *caps)       { return caps->cap_auth_oauth10a == 1; }

void cset_auth_oauthbearer(SMTPCaps *caps,
                           const char *line,
                           int line_len)           { caps->cap_auth_oauthbearer = 1; }
int cget_auth_oauthbearer(const SMTPCaps *caps)    { return caps->cap_auth_oauthbearer == 1; }

void cset_auth_xoauth(SMTPCaps *caps,
                      const char *line,
                      int line_len)                { caps->cap_auth_xoauth = 1; }
int cget_auth_xoauth(const SMTPCaps *caps)         { return caps->cap_auth_xoauth == 1; }

void cset_auth_xoauth2(SMTPCaps *caps,
                       const char *line,
                       int line_len)               { caps->cap_auth_xoauth2 = 1; }
int cget_auth_xoauth2(const SMTPCaps *caps)        { return caps->cap_auth_xoauth2 == 1; }

const CapMatch authstrings[] = {
   {"LOGIN",              5, cset_auth_login},
   {"PLAIN",              5, cset_auth_plain},
   {"PLAIN-CLIENTTOKEN", 17, cset_auth_plain_clienttoken},
   {"GSSAPI",             6, cset_auth_gssapi},
   {"DIGEST-MD5",        10, cset_auth_digest_md5},
   {"MD5",                3, cset_auth_md5},
   {"CRAM-MD5",           8, cset_auth_cram_md5},
   {"OAUTH10A",           8, cset_auth_oauth10a},
   {"OAUTHBEARER",       11, cset_auth_oauthbearer},
   {"XOAUTH",             6, cset_auth_xoauth},
   {"XOAUTH2",            7, cset_auth_xoauth2}
};

int authstrings_count = sizeof(authstrings) / sizeof(CapMatch);

// For debugging purposes, derive an array of capability
// names to report the set capabilities by name

const char *CapNames[] = {
   "starttls",
   "enhancedstatuscodes",
   "8bitmime",
   "7bitmime",
   "pipelining",
   "chunking",
   "smtputf8",
   "size",
   "auth_any",
   "auth_login",
   "auth_plain",
   "auth_plain_clienttoken",
   "auth_gssapi",
   "auth_digest_md5",
   "auth_md5",
   "auth_cram_md5",
   "auth_oauth10a",
   "auth_oauthbearer",
   "auth_xoauth",
   "auth_xoauth2",
   NULL
};

const char *find_end_of_line(const char *line)
{
   const char *ptr = line;
   while (*ptr)
   {
      if (*ptr == '\r' || *ptr == '\n')
         return ptr;
      ++ptr;
   }

   if (!*ptr && ptr > line)
      return ptr-1;

   return NULL;
}

const CapMatch* find_capstring_element(const char *text, int text_len)
{
   const CapMatch *ptr = authstrings;
   const CapMatch *end = authstrings + authstrings_count;

   while (ptr < end)
   {
      if (ptr->len == text_len && 0 == strncasecmp(text, ptr->str, text_len))
         return ptr;

      ++ptr;
   }

   return NULL;
}

typedef struct _capname_search_result
{
   int index;
   const char *ptr_to_value;
} CSResult;

int find_capname_index(CSResult *csr, const char *text)
{
   int clen;
   memset(csr, 0, sizeof(CSResult));

   const char **ptr = CapNames;
   while (*ptr)
   {
      clen = strlen(*ptr);
      if (strncasecmp(*ptr, text, clen) == 0)
      {
         csr->index = ptr - CapNames;

         text += clen;
         if (*text == ' ')
            csr->ptr_to_value = ++text;

         return 1;
      }

      ++ptr;
   }

   return 0;
}

/**
 * Skip forward to next space within range.
 *
 * Return *end* to terminating calling while() loop if no spaces found.
 */
const char *parse_next_space(const char *line, const char *end)
{
   while (line < end)
   {
      if (*line == ' ')
         return line;
      else
         ++line;
   }

   return end;
}

void parse_ehlo_auth(SMTPCaps *caps, const char *auth_line, int line_len)
{
   assert(strncasecmp(auth_line, "AUTH", 4)==0);

   // Skip the 'AUTH ' substring to find the first option:
   const char *ptr = auth_line + 5;

   const char *end = auth_line + line_len;
   const char *next_space;
   char *missing_buffer = NULL;
   int auth_name_len;

   const CapMatch *capmatch_ptr;

   while (ptr < end)
   {
      next_space = parse_next_space(ptr, end);
      auth_name_len = next_space - ptr;

      capmatch_ptr = find_capstring_element(ptr, auth_name_len);
      if (capmatch_ptr)
         (*capmatch_ptr->set_cap)(caps, ptr, auth_name_len);
      else
      {
         if (!missing_buffer)
            missing_buffer = (char*)alloca(line_len);

         strncpy(missing_buffer, ptr, auth_name_len);
         missing_buffer[auth_name_len] = '\0';

         log_error_message(0, "Failed to match authorization type '", missing_buffer, "'", NULL);
      }

      ptr = next_space + 1;
   }
}

void parse_ehlo_response(SMTPCaps *caps, const char *buffer, int data_len)
{
   const char *end = &buffer[data_len];
   const char *ptr = buffer;
   const char *end_of_line;
   int line_len;

   int line_status;
   CSResult csr;

   while (ptr < end)
   {
      end_of_line = find_end_of_line(ptr);
      
      line_status = atoi(ptr);
      if (line_status == 250)
      {
         // Shift to text following status number:
         ptr += 4;

         line_len = end_of_line - ptr;

         if (strncasecmp("auth", ptr, 4) == 0)
            parse_ehlo_auth(caps, ptr, line_len);
         else if (find_capname_index(&csr, ptr))
         {
            int *ptr_cap_field = (int*)caps;
            ptr_cap_field += csr.index;

            if (csr.ptr_to_value)
               *ptr_cap_field = atoi(csr.ptr_to_value);
            else
               *ptr_cap_field = 1;
         }
      }
      else if (line_status >= 400)
      {
         printf("SMTP server error [m34;1m%d[m (%s).\n", line_status, ptr);
      }

      // Go to the next line
      ptr = end_of_line;
      while (isspace(*ptr))
         ++ptr;
   }
}

void show_smtpcaps(const SMTPCaps *caps)
{
   const int *ptr = (const int *)caps;
   const int *end = ptr + sizeof(SMTPCaps) / sizeof(int);
   int index;

   while (ptr < end)
   {
      if (*ptr)
      {
         index = ptr - (const int*)caps;

         printf("[33;1m%s[m is set to [33;1m%d[m.\n",
                CapNames[index], *ptr);
      }

      ++ptr;
   }
  
}


#ifdef SMTP_SETCAPS_MAIN


#include <stdio.h>
#include "logging.c"

void test_parse_ehlo_auth(void)
{
   const char *tstring = "AUTH LOGIN PLAIN XOAUTH2 PLAIN-CLIENTTOKEN OAUTHBEARER XOAUTH";

   SMTPCaps caps;
   memset(&caps, 0, sizeof(SMTPCaps));

   parse_ehlo_auth(&caps, tstring, strlen(tstring));
   show_smtpcaps(&caps);
}

int main(int argc, const char **argv)
{
   test_parse_ehlo_auth();
   return 0;
}


#endif

