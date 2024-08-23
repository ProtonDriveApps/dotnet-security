#ifndef COMMON_H
#define COMMON_H

#include <stdlib.h>

typedef struct Error
{
    int Type;
    const char *Message;
} Error;

Error *alloc_Error();
void free_Error(Error *target);

typedef struct VoidArray
{
    const void *Pointer;
    int Length;
} VoidArray;

VoidArray *alloc_VoidArray();
void empty_VoidArray(VoidArray *target);
void free_VoidArray(VoidArray *target);

typedef struct ArrayResult
{
    Error *Error;
    VoidArray *Array;
} ArrayResult;

ArrayResult *alloc_ArrayResult();
void free_ArrayResult(ArrayResult *target);

#endif /* COMMON_H */
