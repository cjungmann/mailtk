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
   int cap_auth_login;        // use base64 encoding
   int cap_auth_plain;        // use base64 encoding
   int cap_auth_plain_clienttoken;
   int cap_auth_gssapi;
   int cap_auth_digest_md5;
   int cap_auth_md5;
   int cap_auth_cram_md5;
   int cap_auth_oauth10a;
   int cap_auth_oauthbearer;
   int cap_auth_xoauth;
   int cap_auth_xoauth2;
} SMTPCaps;


void cset_starttls(SMTPCaps *caps, const char *line, int line_len);
int cget_starttls(const SMTPCaps *caps);

void cset_chunking(SMTPCaps *caps, const char *line, int line_len);
int cget_chunking(const SMTPCaps *caps);

void cset_enhancedstatuscodes(SMTPCaps *caps, const char *line, int line_len);
int cget_enhancedstatuscodes(const SMTPCaps *caps);

void cset_8bitmime(SMTPCaps *caps, const char *line, int line_len);
int cget_8bitmime(const SMTPCaps *caps);

void cset_7bitmime(SMTPCaps *caps, const char *line, int line_len);
int cget_7bitmime(const SMTPCaps *caps);

void cset_pipelining(SMTPCaps *caps, const char *line, int line_len);
int cget_pipelining(const SMTPCaps *caps);

void cset_smtputf8(SMTPCaps *caps, const char *line, int line_len);
int cget_smtputf8(const SMTPCaps *caps);

void cset_auth_plain(SMTPCaps *caps, const char *line, int line_len);
int cget_auth_plain(const SMTPCaps *caps);

void cset_auth_plain_clienttoken(SMTPCaps *caps, const char *line, int line_len);
int cget_auth_plain_clienttoken(SMTPCaps *caps);

void cset_auth_login(SMTPCaps *caps, const char *line, int line_len);
int cget_auth_login(const SMTPCaps *caps);

void cset_auth_gssapi(SMTPCaps *caps, const char *line, int line_len);
int cget_auth_gssapi(const SMTPCaps *caps);

void cset_auth_digest_md5(SMTPCaps *caps, const char *line, int line_len);
int cget_auth_digest_md5(const SMTPCaps *caps);

void cset_auth_md5(SMTPCaps *caps, const char *line, int line_len);
int cget_auth_md5(const SMTPCaps *caps);

void cset_auth_cram_md5(SMTPCaps *caps, const char *line, int line_len);
int cget_auth_cram_md5(const SMTPCaps *caps);

void cset_auth_oauth10a(SMTPCaps *caps, const char *line, int line_len);
int cget_auth_oauth10a(const SMTPCaps *caps);

void cset_auth_oauthbearer(SMTPCaps *caps, const char *line, int line_len);
int cget_auth_oauthbearer(const SMTPCaps *caps);

void cset_auth_xoauth(SMTPCaps *caps, const char *line, int line_len);
int cget_auth_xoauth(const SMTPCaps *caps);

void cset_auth_xoauth2(SMTPCaps *caps, const char *line, int line_len);
int cget_auth_xoauth2(const SMTPCaps *caps);


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
