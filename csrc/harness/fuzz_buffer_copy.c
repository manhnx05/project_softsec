#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "buffer_copy.h"

static uint32_t next_value(uint32_t *state)
{
    uint32_t value = *state;
    value ^= value << 13;
    value ^= value >> 17;
    value ^= value << 5;
    *state = value;
    return value;
}

int main(int argument_count, char **arguments)
{
    char *end = NULL;
    unsigned long iterations = 10000UL;
    unsigned long iteration;
    uint32_t seed = UINT32_C(0x00C0FFEE);
    uint32_t random_state;

    if (argument_count > 1) {
        iterations = strtoul(arguments[1], &end, 10);
        if (end == arguments[1] || *end != '\0' || iterations == 0UL
            || iterations > 1000000UL) {
            (void)fprintf(stderr, "Invalid iteration count.\n");
            return 64;
        }
    }
    if (argument_count > 2) {
        unsigned long parsed_seed;
        end = NULL;
        parsed_seed = strtoul(arguments[2], &end, 10);
        if (end == arguments[2] || *end != '\0' || parsed_seed > UINT32_MAX) {
            (void)fprintf(stderr, "Invalid seed.\n");
            return 64;
        }
        seed = (uint32_t)parsed_seed;
    }
    random_state = seed == 0U ? UINT32_C(1) : seed;

    for (iteration = 0UL; iteration < iterations; ++iteration) {
        unsigned char source[BUFFER_COPY_CAPACITY];
        unsigned char destination[BUFFER_COPY_CAPACITY];
        unsigned char original_destination[BUFFER_COPY_CAPACITY];
        int length;
        int result;
        size_t index;
        int expected_success;

        for (index = 0U; index < BUFFER_COPY_CAPACITY; ++index) {
            source[index] = (unsigned char)next_value(&random_state);
            destination[index] = UINT8_C(0xA5);
            original_destination[index] = UINT8_C(0xA5);
        }

        switch (iteration % 8UL) {
        case 0UL:
            length = INT_MIN;
            break;
        case 1UL:
            length = -1;
            break;
        case 2UL:
            length = 0;
            break;
        case 3UL:
            length = BUFFER_COPY_CAPACITY;
            break;
        case 4UL:
            length = BUFFER_COPY_CAPACITY + 1;
            break;
        case 5UL:
            length = INT_MAX;
            break;
        default:
            length = (int)(next_value(&random_state) % UINT32_C(97)) - 48;
            break;
        }

        result = copy_buffer(
            source,
            sizeof(source),
            destination,
            sizeof(destination),
            length
        );
        expected_success = length >= 0 && length <= BUFFER_COPY_CAPACITY;
        if ((result == BUFFER_COPY_OK) != expected_success) {
            (void)fprintf(stderr, "Unexpected result for length %d.\n", length);
            return 1;
        }

        if (expected_success) {
            if (memcmp(destination, source, (size_t)length) != 0) {
                (void)fprintf(stderr, "Copied bytes differ at length %d.\n", length);
                return 1;
            }
        } else if (memcmp(destination, original_destination, sizeof(destination)) != 0) {
            (void)fprintf(stderr, "Rejected input changed the destination.\n");
            return 1;
        }
    }

    (void)printf(
        "PASS: %lu iterations completed with seed %u.\n",
        iterations,
        (unsigned int)seed
    );
    return 0;
}
