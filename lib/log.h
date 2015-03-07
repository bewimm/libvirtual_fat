#ifndef H_LOG
#define H_LOG

#include <stdio.h>

#define LOG_ERR(...) do{fprintf(stderr, __VA_ARGS__); printf("\n");}while(0)


#endif
