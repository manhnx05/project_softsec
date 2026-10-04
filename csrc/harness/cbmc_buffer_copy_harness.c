#include "buffer_copy.h"

extern int nondet_int(void);

int main(void)
{
    unsigned char source[BUFFER_COPY_CAPACITY] = {0U};
    unsigned char destination[BUFFER_COPY_CAPACITY] = {0U};
    int length = nondet_int();

    (void)copy_buffer(
        source,
        sizeof(source),
        destination,
        sizeof(destination),
        length
    );
    return 0;
}
