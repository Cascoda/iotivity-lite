#include <stddef.h>
#include <malloc.h>


#define MALLOC_WRAPPER_HEAP_SIZE 0xa200

void *__real_malloc (size_t __size);

void *__wrap_malloc (size_t __size)
{
    struct mallinfo info;
    info = mallinfo();

    printf("m %d, h %d\n", __size, info.uordblks);

    if (info.uordblks + __size > MALLOC_WRAPPER_HEAP_SIZE)
    {
        printf("ERROR: OOM while allocating %d bytes!\n", __size);
        printf("Heap allocated so far: %d\n", info.uordblks);
        //return NULL;
        return __real_malloc(__size);
    }
    else
    {
        return __real_malloc(__size);
    }

}