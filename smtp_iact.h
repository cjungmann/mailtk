#ifndef SMTP_IACT_H
#define SMTP_IACT_H

#include "linedrop.h"

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

/**
 * Callback function through which a RecipLink chain is returned.
 */
typedef void (*RecipChainUser)(RecipLink *chain, void *data);

void build_recip_chain(LineDrop *ld, void *data, RecipChainUser callback);


#endif
