#ifndef LMS_BUFFER_COPY_H
#define LMS_BUFFER_COPY_H

#include <stddef.h>

#define BUFFER_COPY_CAPACITY 16

enum buffer_copy_result {
    BUFFER_COPY_OK = 0,
    BUFFER_COPY_INVALID_ARGUMENT = -1,
    BUFFER_COPY_NEGATIVE_LENGTH = -2,
    BUFFER_COPY_OUT_OF_RANGE = -3
};

int copy_buffer(
    const unsigned char *source,
    size_t source_size,
    unsigned char *destination,
    size_t destination_capacity,
    int length
);

#endif
