#ifndef ERRPRINTF_H
#define ERRPRINTF_H

#include <stdarg.h>
#include <stdio.h>
#include <unistd.h>


/*
    Formats the message and prints it to sdterr, then flushes stderr.
*/
void errprintf(const char *format, ...);

/*
    Same as errprintf(), but also terminates the program.
*/
void errprintf_die(int code, const char *format, ...);


#endif
