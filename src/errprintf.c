#include "errprintf.h"


void errprintf(const char *format, ...) {
    va_list args;

    va_start(args, format);
    vfprintf(stderr, format, args);
    va_end(args);

    fflush(stderr);
}

void errprintf_die(int code, const char *format, ...) {
    va_list args;

    va_start(args, format);
    vfprintf(stderr, format, args);
    va_end(args);

    fflush(stderr);

    _exit(code);
}
