#include "gopenpgp.h"

SessionKey *alloc_SessionKey()
{
    return (SessionKey *)calloc(1, sizeof(SessionKey));
}

void free_SessionKey(SessionKey *target)
{
    if (target->Data.Pointer) free((void *)target->Data.Pointer);
    if (target->AlgorithmId) free((void *)target->AlgorithmId);
    free(target);
}

SessionKeyResult *alloc_SessionKeyResult()
{
    return (SessionKeyResult *)calloc(1, sizeof(SessionKeyResult));
}

void free_SessionKeyResult(SessionKeyResult *target)
{
    if (target->Error) free_Error(target->Error);
    if (target->SessionKey) free_SessionKey(target->SessionKey);
    free(target);
}

KeyPacketGenerationResult *alloc_KeyPacketGenerationResult()
{
    return (KeyPacketGenerationResult *)calloc(1, sizeof(KeyPacketGenerationResult));
}

void free_KeyPacketGenerationResult(KeyPacketGenerationResult *target)
{
    if (target->Error) free_Error(target->Error);
    if (target->KeyPacket) free_VoidArray(target->KeyPacket);
    if (target->SessionKey) free_SessionKey(target->SessionKey);
    free(target);
}

EncryptionResult *alloc_EncryptionResult()
{
    return (EncryptionResult *)calloc(1, sizeof(EncryptionResult));
}

void free_EncryptionResult(EncryptionResult *target)
{
    if (target->Error) free((void *)target->Error);
    if (target->EncryptionOutput) free_VoidArray(target->EncryptionOutput);

    VoidArray* detachedSignature = target->DetachedSignature;
    if (detachedSignature)
    {
        if (detachedSignature->Pointer) free((void *)detachedSignature->Pointer);
        free(detachedSignature);
    }

    if (target->SessionKey) free_SessionKey(target->SessionKey);
    free(target);
}

DecryptionOutput *alloc_DecryptionOutput()
{
    return (DecryptionOutput *)calloc(1, sizeof(DecryptionOutput));
}

void free_DecryptionOutput(DecryptionOutput *target)
{
    if (target->SessionKey) free_SessionKey(target->SessionKey);
    empty_VoidArray(&target->DecryptedData);
    free(target);
}

VerificationOutput *alloc_VerificationOutput()
{
    return (VerificationOutput *)calloc(1, sizeof(VerificationOutput));
}

void free_VerificationOutput(VerificationOutput *target)
{
    if (target->Message) free((void *)target->Message);
    free(target);
}

DecryptionResult *alloc_DecryptionResult()
{
    return (DecryptionResult *)calloc(1, sizeof(DecryptionResult));
}

void free_DecryptionResult(DecryptionResult *target)
{
    if (target->Error) free_Error(target->Error);
    if (target->DecryptionOutput) free_DecryptionOutput(target->DecryptionOutput);
    if (target->VerificationOutput) free_VerificationOutput(target->VerificationOutput);
    free(target);
}

VerificationResult *alloc_VerificationResult()
{
    return (VerificationResult *)calloc(1, sizeof(VerificationResult));
}

void free_VerificationResult(VerificationResult *target)
{
    if (target->Error) free_Error(target->Error);
    if (target->VerificationOutput) free_VerificationOutput(target->VerificationOutput);
    free(target);
}
