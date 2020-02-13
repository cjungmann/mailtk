// -*- compile-command: "base=logging; gcc -Wall -Werror -ggdb -DLOGGING_MAIN -U NDEBUG -o $base ${base}.c" -*-

#include <stdio.h>
#include <stdarg.h>
#include "logging.h"

void raw_log_message(FILE *target, ...)
{
   const char *str;
   va_list ap;
   va_start(ap, target);

   while ((str = va_arg(ap, char*)))
      fputs(str, target);

   fputc('\n', target);

   va_end(ap);
}

void log_error_message(int level, ...)
{
   const char *str;
   va_list ap;
   va_start(ap, level);

   while ((str = va_arg(ap, char*)))
      fputs(str, stderr);

   fputc('\n', stderr);

   va_end(ap);
}

#ifdef LOGGING_MAIN
int main(int argc, const char **argv)
{
   printf("This is a message to stdout.\n");
   raw_log_message(stderr, "This is a message ", "to stderr", NULL);
   
   return 0;
}
#endif
