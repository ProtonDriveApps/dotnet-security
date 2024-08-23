#include "srp.h"

ProofGenerationResult *alloc_ProofGenerationResult()
{
    return (ProofGenerationResult *)calloc(1, sizeof(ProofGenerationResult));
}

void free_ProofGenerationResult(ProofGenerationResult *target)
{
    if (target->ClientProof) free_VoidArray(target->ClientProof);
    if (target->ClientEphemeral) free_VoidArray(target->ClientEphemeral);
    if (target->ExpectedServerProof) free_VoidArray(target->ExpectedServerProof);
    if (target->Error) free_Error(target->Error);
    free(target);
}
