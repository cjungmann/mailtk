#ifndef SMTP_SETCAPS_H
#define SMTP_SETCAPS_H


typedef struct _smtp_caps
{
   /** Server-reported capabilities */
   int cap_starttls;
   int cap_enhancedstatuscodes;
   int cap_8bitmime;
   int cap_7bitmime;
   int cap_pipelining;
   int cap_chunking;
   int cap_smtputf8;
   int cap_size;
   int cap_auth_any;
   int cap_auth_plain;        // use base64 encoding
   int cap_auth_login;        // use base64 encoding
   int cap_auth_gssapi;
   int cap_auth_digest_md5;
   int cap_auth_md5;
   int cap_auth_cram_md5;
   int cap_auth_oauth10a;
   int cap_auth_oauthbearer;
   int cap_auth_xoauth;
   int cap_auth_xoauth2;
} SMTPCaps;



typedef void (*scap_setter)(SMTPCaps *caps, const char *line, int line_len);


void parse_ehlo_response(SMTPCaps *caps, const char *buffer, int data_len);
void show_smtpcaps(const SMTPCaps *caps);

typedef struct _cap_match
{
   const char  *str;
   int         len;
   scap_setter set_cap;
} CapMatch;


#endif
