#ifndef SMTP_IACT_H
#define SMTP_IACT_H

#include "linedrop.h"
#include "socktalk.h"

typedef enum _smtp_recipient_types
{
   RT_TO = 0,   // no address prefix character
   RT_CC,       // '+' prefix   (e.g. +recipient@gmail.com)
   RT_BCC,      // '-' prefix   (e.g. -recipient@gmail.com)
   RT_IGNORE    // '#' prefix   (e.g. #recipient@gmail.com)
} RecipType;

typedef struct _smtp_recipient_link
{
   RecipType                   rtype;
   const char                  *address;
   int                         smtp_status;
   struct _smtp_recipient_link *next;
} RecipLink;

typedef struct _smtp_header_value_link
{
   const char                     *value;
   struct _smtp_header_value_link *next;
} HeaderValue;

typedef struct _smtp_header_link
{
   const char  *name;
   HeaderValue *value;
} HeaderLink;

typedef struct _smtp_recips_and_headers
{
   const RecipLink  *recip_chain;
   const HeaderLink *header_chain;
} RecipHeader;

/**
 * Callback function through which a RecipLink chain is returned.
 */
typedef void (*RecipChainUser)(RecipLink *chain, void *data);
void build_recip_chain(RecipChainUser callback, LineDrop *ld, void *data);

int count_unignored_recips(const RecipLink *chain);
void smtp_send_headers(LineDrop *ld, STalker *stalker, RecipLink *rchain);


/**
 * Introduce an email, requesting server permission to send to each address in recipient_chain.
 * The result of each request is saved in the RecipLink, and the number of accepeted addresses
 * will be returned by the function to use as a signal about whether or not to continue sending
 * the email.
 */
int smtp_send_envelope(STalker *stalker, const char *from, RecipLink *recipient_chain);
















#endif
