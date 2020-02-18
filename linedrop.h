#ifndef LINESERVE_H
#define LINESERVE_H

typedef void (*ls_line_dropper)(const char *linestr, int line_len);

typedef struct _line_drop
{
   void            *data;
   ls_line_dropper dropline;
} LineDrop;


const char *string_find_line_end(const char *line, const char *end_of_data);

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

int stream_get_current_line(const StreamLineDropper *sld, const char **line, int *line_len);
int stream_advance(StreamLineDropper *sld);





#endif
