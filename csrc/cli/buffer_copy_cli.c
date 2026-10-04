#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>

#include "buffer_copy.h"

int main(int argument_count, char **arguments)
{
    unsigned char source[BUFFER_COPY_CAPACITY] = {0U};
    unsigned char destination[BUFFER_COPY_CAPACITY] = {0U};
    char *end = NULL;
    long parsed_length;
    int result;

    if (argument_count != 2) {
        (void)fprintf(stderr, "Usage: buffer_copy_cli <length>\n");
        return 64;
    }

    errno = 0;
    parsed_length = strtol(arguments[1], &end, 10);
    if (errno != 0 || end == arguments[1] || *end != '\0'
        || parsed_length < INT_MIN || parsed_length > INT_MAX) {
        (void)fprintf(stderr, "Invalid integer length.\n");
        return 64;
    }

    result = copy_buffer(
        source,
        sizeof(source),
        destination,
        sizeof(destination),
        (int)parsed_length
    );
    if (result != BUFFER_COPY_OK) {
        (void)fprintf(stderr, "Copy rejected with code %d.\n", result);
        return 2;
    }

    (void)printf("Copied %ld bytes.\n", parsed_length);
    return 0;
}
