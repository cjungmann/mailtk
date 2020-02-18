// -*- compile-command: "base=linedrop; gcc -Wall -Werror -ggdb -DLINEDROP_MAIN -U NDEBUG -o $base ${base}.c" -*-

#include <stdio.h>     // for fread()
#include <string.h>    // for memmove()
#include "linedrop.h"

const char *string_find_line_end(const char *line, const char *end_of_data)
{
   while (line < end_of_data && *line != '\n')
      ++line;

   if (*line == '\n')
   {
      if (*(line-1) == '\r')
         --line;

      return line;
   }
   else
      return NULL;
}

void stream_init_dropper(StreamLineDropper *sld, FILE *stream, char *buffer, int buffer_len)
{
   memset(sld, 0, sizeof(StreamLineDropper));

   // Populate struct members
   sld->stream = stream;
   sld->buffer = buffer;
   sld->buffer_end = buffer + buffer_len;
   sld->data_end = buffer;
   sld->cur_line = buffer;
   sld->cur_line_end  = NULL;

   if (stream_top_up_buffer(sld))
      sld->cur_line_end = string_find_line_end(sld->buffer, sld->buffer_end);
}

int stream_top_up_buffer(StreamLineDropper *sld)
{
   int bytes_remaining;
   int bytes_to_read, bytes_read;
   const char *temp_end = NULL;

   if (sld->stream)
   {
      bytes_remaining = sld->data_end - sld->cur_line;
      memmove(sld->buffer, sld->cur_line, bytes_remaining);
      sld->cur_line = sld->buffer;

      temp_end = sld->buffer + bytes_remaining;
      bytes_to_read = sld->buffer_end - temp_end;

      bytes_read = fread((char*)temp_end, 1, bytes_to_read, sld->stream);
      if (bytes_read)
      {
         sld->data_end = temp_end + bytes_read;
         temp_end = string_find_line_end(sld->buffer, sld->data_end);
      }

      if (temp_end)
         sld->cur_line_end = temp_end;
      else
         sld->cur_line_end = sld->data_end;

      if (bytes_read < bytes_to_read)
      {
         // The calling function should close the stream,
         // so we'll use the struct member as a flag indicating
         // data exhaustion
         if (feof(sld->stream))
            sld->stream = NULL;
      }

      return 1;
   }

   return 0;
}

int stream_advance(StreamLineDropper *sld)
{
   // Find the beginning of the next line by skipping past end-of-line characters
   const char *ptr = sld->cur_line_end;
   if (*ptr == '\r')
      ++ptr;
   if (*ptr == '\n')
      ++ptr;

   if (ptr < sld->data_end)
   {
      sld->cur_line = ptr;
      sld->cur_line_end = string_find_line_end(ptr, sld->data_end);

      if (sld->cur_line_end)
         return 1;
      else
         return stream_top_up_buffer(sld);
   }
   else
      return stream_top_up_buffer(sld);
}

int stream_get_current_line(const StreamLineDropper *sld, const char **line, int *line_len)
{
   if (sld->cur_line && sld->cur_line_end)
   {
      *line = sld->cur_line;
      *line_len = sld->cur_line_end - sld->cur_line;
      return 1;
   }

   return 0;
}
   


#ifdef LINEDROP_MAIN

#include <stdio.h>

int main(int argc, const char **argv)
{
   char              buffer[1024];
   StreamLineDropper sld;

   FILE *stream = fopen("linedrop.c", "r");

   const char *line;
   int line_len;
   
   // Debugging variablesxs
   char              debugbuffer[1024];
   int               current_line = 0;


   if (stream)
   {
      stream_init_dropper(&sld, stream, buffer, sizeof(buffer));

      do
      {
         stream_get_current_line(&sld, &line, &line_len);

         ++current_line;

         // For gdb display 
         memset(debugbuffer, 0, sizeof(debugbuffer));
         sprintf(debugbuffer, "%3d %.*s", current_line, line_len, line);

         // For std display
         printf("%3d [32;1m%.*s[m\n", current_line, line_len, line);
      }
      while(stream_advance(&sld));

      fclose(stream);
   }


   return 0;
}

#endif
