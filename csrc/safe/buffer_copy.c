#include <string.h>

#include "buffer_copy.h"

int copy_buffer(
    const unsigned char *source,
    size_t source_size,
    unsigned char *destination,
    size_t destination_capacity,
    int length
)
{
    size_t copy_length;

    if (source == NULL || destination == NULL) {
        return BUFFER_COPY_INVALID_ARGUMENT;
    }

    if (length < 0) {
        return BUFFER_COPY_NEGATIVE_LENGTH;
    }

    copy_length = (size_t)length;
    if (copy_length > source_size || copy_length > destination_capacity) {
        return BUFFER_COPY_OUT_OF_RANGE;
    }

    memcpy(destination, source, copy_length);
    return BUFFER_COPY_OK;
}
