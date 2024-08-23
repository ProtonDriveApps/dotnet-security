#include "common.h"

Error *alloc_Error()
{
    return (Error *)calloc(1, sizeof(Error));
}

void free_Error(Error *error)
{
    if (error->Message) free((void *)error->Message);
    free(error);
}

VoidArray *alloc_VoidArray()
{
    return (VoidArray *)calloc(1, sizeof(VoidArray));
}

void empty_VoidArray(VoidArray *array)
{
    if (array->Pointer) free((void *)array->Pointer);
}

void free_VoidArray(VoidArray *array)
{
    empty_VoidArray(array);
    free(array);
}

ArrayResult *alloc_ArrayResult()
{
    return (ArrayResult *)calloc(1, sizeof(ArrayResult));
}

void free_ArrayResult(ArrayResult *target)
{
    if (target->Error) free((void *)target->Error);
    if (target->Array) free_VoidArray(target->Array);
    free(target);
}
