#ifndef LOGGING_H
#define LOGGING_H

void raw_log_message(FILE *target, ...);
void log_error_message(int level, ...);

#endif
