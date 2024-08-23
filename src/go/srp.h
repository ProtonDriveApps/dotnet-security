#ifndef SRP_H
#define SRP_H

#include <stdlib.h>
#include "common.h"

typedef struct ProofGenerationResult
{
    Error *Error;
    VoidArray *ClientProof;
    VoidArray *ClientEphemeral;
    VoidArray *ExpectedServerProof;
} ProofGenerationResult;

ProofGenerationResult *alloc_ProofGenerationResult();
void free_ProofGenerationResult(ProofGenerationResult *target);

#endif /* SRP_H */