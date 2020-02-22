#ifndef LINEDROP_H
#define LINEDROP_H

#include <stdio.h>
#include <string.h> // for memset

struct _line_drop;

typedef int (*dropper_advance)(void *obj);
typedef int (*dropper_get_line)(void *obj, const char **linestr, int *line_len);
typedef int (*dropper_spent)(const void *obj);

// This function, if implemented, indicates if the loop should continue.
// That is, return non-zero to continue looping, 0 to terminate.
typedef int (*dropper_break_check)(const struct _line_drop *ld);

typedef struct _line_drop
{
   void                *data;
   dropper_advance     advance;
   dropper_get_line    get_line;
   dropper_spent       is_spent;
   dropper_break_check break_check;
} LineDrop;

// Built-in implementation of dropper_break_check for an empty line:
int LineDrop_break_on_empty_line(const LineDrop *ld);

void DropInitialize(LineDrop *new_line_drop,
                    void *data,
                    dropper_advance advance_func,
                    dropper_get_line get_line_func,
                    dropper_spent spent_func,
                    dropper_break_check break_check_func);

static inline int DropAdvance(void *obj)
{
   LineDrop *ld = (LineDrop*)obj;
   return ld->advance(ld->data) && (!ld->break_check || !ld->break_check(ld));
}

static inline int DropGetLine(const void *obj, const char **line, int *line_len)
{
   const LineDrop *ld = (LineDrop*)obj;
   return ld->get_line(ld->data, line, line_len);
}


const char *string_find_line_end(const char *line, const char *end_of_data);

/**********************
 * Stream Line Dropper
 *********************/

// "Class" StreamLineDropper
typedef struct _stream_dropper
{
   FILE *stream;
   char *buffer;
   const char *buffer_end;
   const char *data_end;
   const char *cur_line;
   const char *cur_line_end;
} StreamLineDropper;

void stream_init_dropper(StreamLineDropper *sld, FILE *stream, char *buffer, int buffer_len);
int stream_top_up_buffer(StreamLineDropper *sld);

int stream_get_line(const StreamLineDropper *sld, const char **line, int *line_len);
int stream_advance(StreamLineDropper *sld);
int stream_spent(const StreamLineDropper *sld);

// Implement LineDrop
void init_stream_line_drop(LineDrop *ld, StreamLineDropper *sld);
int ld_stream_get_line(void *sld, const char **line, int *line_len);
int ld_stream_advance(void *sld);
int ld_stream_spent(const void *sld);


/***************************
 * String List Line Dropper
 **************************/

typedef struct _list_dropper
{
   const char **source;
   const char **current;
} ListLineDropper;

void list_init_dropper(ListLineDropper *lld, const char **source);

int list_get_line(ListLineDropper *lld, const char **line, int *line_len);
int list_advance(ListLineDropper *lld);
int list_spent(const ListLineDropper *lld);

// Implement LineDrop
void init_list_line_drop(LineDrop *ld, ListLineDropper *lld);
int ld_list_get_line(void *sld, const char **line, int *line_len);
int ld_list_advance(void *sld);
int ld_list_spent(const void *sld);



#endif
