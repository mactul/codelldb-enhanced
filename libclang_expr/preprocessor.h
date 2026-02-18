#ifndef _PREPROCESSOR_H
#define _PREPROCESSOR_H

#include <stddef.h>

char* preprocess_expression(const char* file_content_before, size_t file_content_size, const char* expression);

#endif