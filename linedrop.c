// -*- compile-command: "base=linedrop; gcc -Wall -Werror -ggdb -DLINEDROP_MAIN -DDEBUG -o $base ${base}.c" -*-

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

/***********
 * LineDrop 
 **********/

int LineDrop_break_on_empty_line(const LineDrop *ld)
{
   const char *line;
   int line_len;
   if (DropGetLine(ld, &line, &line_len))
      return line_len==0;
   else
      return 0;
}

void DropInitialize(LineDrop            *new_line_drop,
                    void                *data,
                    dropper_advance     advance_func,
                    dropper_get_line    get_line_func,
                    dropper_spent       spent_func,
                    dropper_break_check break_check_func)
{
   memset(new_line_drop, 0, sizeof(LineDrop));

   new_line_drop->data     = data;
   new_line_drop->advance  = advance_func;
   new_line_drop->get_line = get_line_func;
   new_line_drop->is_spent = spent_func;

   if (break_check_func)
      new_line_drop->break_check = break_check_func;
   else
      new_line_drop->break_check = LineDrop_break_on_empty_line;
}


/**********************
 * Stream Line Dropper
 *********************/

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

int stream_get_line(const StreamLineDropper *sld, const char **line, int *line_len)
{
   if (sld->cur_line && sld->cur_line_end)
   {
      *line = sld->cur_line;
      *line_len = sld->cur_line_end - sld->cur_line;
      return 1;
   }

   return 0;
}

int stream_spent(const StreamLineDropper *sld)
{
   return sld->stream == NULL;
}

/** LineDrop functions for StreamLineDropper */

void init_stream_line_drop(LineDrop *ld, StreamLineDropper *sld)
{
   DropInitialize(ld,
                  sld,
                  ld_stream_advance,
                  ld_stream_get_line,
                  ld_stream_spent, NULL);
}

int ld_stream_get_line(void *sld, const char **line, int *line_len)
{
   return stream_get_line((StreamLineDropper*)sld, line, line_len);
}

int ld_stream_advance(void *sld)
{
   return stream_advance((StreamLineDropper*)sld);
}

int ld_stream_spent(const void *sld)
{
   return stream_spent((const StreamLineDropper*)sld);
}


/***************************
 * String List Line Dropper
 **************************/

void list_init_dropper(ListLineDropper *lld, const char **source)
{
   memset(lld, 0, sizeof(ListLineDropper));
   lld->source = lld->current = source;
}

int list_get_line(ListLineDropper *lld, const char **line, int *line_len)
{
   if (*lld->current)
   {
      *line = *lld->current;
      *line_len = strlen(*line);
      return 1;
   }
   else
      return 0;
}

int list_advance(ListLineDropper *lld)
{
   if (*lld->current && *++lld->current)
      return 1;
   else
      return 0;
}

int list_spent(const ListLineDropper *lld)
{
   return *lld->current == NULL;
}

/** LineDrop functions for ListLineDropper */

/**
 * Prepare an uninitialized LineDrop 'object' with an initialized ListLineDropper.
 *
 * Besides installing the appropriate function pointers for ListLineDropper,
 * this function also sets a default break check function that
 * causes DropAdvance to return 0 when an empty line is encountered.
 *
 * Other applications may want to break on another condition, or not
 * break at all, which would require a custom function or setting
 * LineDrop::break_check to NULL, respectively.
 *
 * Look at linedrop.h for the dropper_break_check function pointer typedef.
 */
void init_list_line_drop(LineDrop *ld, ListLineDropper *lld)
{
   DropInitialize(ld,
                  lld,
                  ld_list_advance,
                  ld_list_get_line,
                  ld_list_spent,
                  NULL);
}

int ld_list_get_line(void *sld, const char **line, int *line_len)
{
   return list_get_line((ListLineDropper*)sld, line, line_len);
}

int ld_list_advance(void *sld)
{
   return list_advance((ListLineDropper*)sld);
}

int ld_list_spent(const void *sld)
{
   return list_spent((ListLineDropper*)sld);
}

/************************************
 * Conditionally-compiled test code.
 ***********************************/

#ifdef LINEDROP_MAIN

#include <stdio.h>

void test_with_stream(void)
{
   // Generic LineDrop variables
   const char *line;
   int line_len;
   
   // Debugging variablesxs
   char              debugbuffer[1024];
   int               current_line = 0;

   // Stream Dropper-specific variables
   char              buffer[1024];
   StreamLineDropper sld;
   LineDrop          ld;

   FILE *stream = fopen("linedrop.c", "r");
   if (stream)
   {
      stream_init_dropper(&sld, stream, buffer, sizeof(buffer));
      init_stream_line_drop(&ld, &sld);
      do
      {
         DropGetLine(&ld, &line, &line_len);

         ++current_line;

         // For gdb display 
         memset(debugbuffer, 0, sizeof(debugbuffer));
         sprintf(debugbuffer, "%3d %.*s", current_line, line_len, line);

         // For std display
         printf("%3d [32;1m%.*s[m\n", current_line, line_len, line);
      }
      while(DropAdvance(&ld));

      fclose(stream);
   }
 }

void test_with_string_list(void)
{
   /**
    * Create a LineDrop with a null-terminated string array
    */
   const char *llist[] = {
      "This is the first line.",
      "This is the second line.",
      "This is the third line.",
      "This is the fourth line.",
      "This is the fifth line.",
      "",
      "This sixth line should not appear after the empty line.",
      NULL
   };

   ListLineDropper lld;
   LineDrop        ld;

   list_init_dropper(&lld, llist);
   init_list_line_drop(&ld, &lld);

   ld.break_check = LineDrop_break_on_empty_line;

   // LineDrop object, ld, is ready to use


   // Generic LineDrop variables
   const char *line;
   int line_len;
   
   // Debugging variablesxs
   char              debugbuffer[1024];
   int               current_line = 0;
   
   do
   {
      DropGetLine(&ld, &line, &line_len);

      ++current_line;

      // For gdb display 
      memset(debugbuffer, 0, sizeof(debugbuffer));
      sprintf(debugbuffer, "%3d %.*s", current_line, line_len, line);

      // For std display
      printf("%3d [32;1m%.*s[m\n", current_line, line_len, line);
   }
   while(DropAdvance(&ld));

 }

int main(int argc, const char **argv)
{
   /* test_with_stream(); */

   test_with_string_list();

   return 0;
}

#endif
