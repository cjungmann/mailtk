#ifndef LINESERVE_H
#define LINESERVE_H

typedef int (*dropper_advance)(void *obj);
typedef int (*dropper_get_line)(void *obj, const char **linestr, int *line_len);

typedef struct _line_drop
{
   void             *data;
   dropper_advance  advance;
   dropper_get_line get_line;
} LineDrop;

static inline int DropAdvance(void *obj)
{
   LineDrop *ld = (LineDrop*)obj;
   return ld->advance(ld->data);
}

static inline int DropGetLine(void *obj, const char **line, int *line_len)
{
   LineDrop *ld = (LineDrop*)obj;
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

// Implement LineDrop

int ld_stream_get_line(void *sld, const char **line, int *line_len)
{
   return stream_get_line((StreamLineDropper*)sld, line, line_len);
}

int ld_stream_advance(void *sld)
{
   return stream_advance((StreamLineDropper*)sld);
}

void init_stream_line_drop(LineDrop *ld, StreamLineDropper *sld)
{
   memset(ld, 0, sizeof(LineDrop));
   ld->data = (void*)sld;
   ld->advance = ld_stream_advance;
   ld->get_line = ld_stream_get_line;
}


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

// Implement LineDrop

int ld_list_get_line(void *sld, const char **line, int *line_len)
{
   return list_get_line((ListLineDropper*)sld, line, line_len);
}

int ld_list_advance(void *sld)
{
   return list_advance((ListLineDropper*)sld);
}

void init_list_line_drop(LineDrop *ld, ListLineDropper *lld)
{
   memset(ld, 0, sizeof(LineDrop));
   ld->data = (void*)lld;
   ld->advance = ld_list_advance;
   ld->get_line = ld_list_get_line;
}



#endif
