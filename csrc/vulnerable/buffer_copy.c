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
    (void)source_size;

    if (source == NULL || destination == NULL) {
        return BUFFER_COPY_INVALID_ARGUMENT;
    }

    if (length > (int)destination_capacity) {
        return BUFFER_COPY_OUT_OF_RANGE;
    }

    /*
     * Intentionally vulnerable lab example: a negative signed length passes
     * the check and converts to a huge size_t at the memcpy call.
     */
    memcpy(destination, source, (size_t)length);
    return BUFFER_COPY_OK;
}
