#ifndef GOPENPGP_H
#define GOPENPGP_H

#include <stdlib.h>
#include "common.h"

typedef struct PrivateKey
{
    VoidArray Data;
    int IsArmored;
    VoidArray Passphrase;
} PrivateKey;

typedef struct PublicKey
{
    VoidArray Data;
    int IsArmored;
} PublicKey;

typedef struct SessionKey
{
    const char *AlgorithmId;
    VoidArray Data;
} SessionKey;

SessionKey *alloc_SessionKey();

typedef struct SessionKeyResult
{
    Error *Error;
    SessionKey *SessionKey;
} SessionKeyResult;

SessionKeyResult *alloc_SessionKeyResult();
void free_SessionKeyResult(SessionKeyResult *target);

typedef struct EncryptionInput
{
    const PublicKey *PublicKey;
    const SessionKey *SessionKey;
    const VoidArray *Password;
    VoidArray PlainData;
    int MessageMustBeArmored;
    int MessageMustBeCompressed;
    const char *Name;
} EncryptionInput;

typedef struct SignatureDetachmentInput
{
    const PublicKey *PublicKeyForEncryption;
    int IsArmored;
} SignatureDetachmentInput;

typedef struct SignatureInput
{
    const PrivateKey *PrivateKey;
    const SignatureDetachmentInput *Detachment;
} SignatureInput;

typedef struct KeyPacketGenerationResult
{
    Error *Error;
    SessionKey *SessionKey;
    VoidArray *KeyPacket;
} KeyPacketGenerationResult;

KeyPacketGenerationResult *alloc_KeyPacketGenerationResult();
void free_KeyPacketGenerationResult(KeyPacketGenerationResult *target);

typedef struct EncryptionResult
{
    Error *Error;
    VoidArray *EncryptionOutput;
    VoidArray *DetachedSignature;
    SessionKey *SessionKey;
} EncryptionResult;

EncryptionResult *alloc_EncryptionResult();
void free_EncryptionResult(EncryptionResult *target);

typedef struct Signature
{
    VoidArray Data;
    int IsEncrypted;
    int IsArmored;
} Signature;

typedef struct DecryptionInput
{
    const PrivateKey *PrivateKeys;
    int PrivateKeysLength;
    const VoidArray *Password;
    VoidArray Message;
    int MessageIsArmored;
} DecryptionInput;

typedef struct DecryptionOutput
{
    VoidArray DecryptedData;
    SessionKey *SessionKey;
} DecryptionOutput;

DecryptionOutput *alloc_DecryptionOutput();

typedef struct VerificationInput
{
    const PublicKey *PublicKeys;
    int PublicKeysLength;
    const Signature *DetachedSignature;
} VerificationInput;

typedef struct VerificationOutput
{
    int Code;
    const char *Message;
} VerificationOutput;

VerificationOutput *alloc_VerificationOutput();

typedef struct DecryptionResult
{
    Error *Error;
    DecryptionOutput *DecryptionOutput;
    VerificationOutput *VerificationOutput;
} DecryptionResult;

DecryptionResult *alloc_DecryptionResult();
void free_DecryptionResult(DecryptionResult *target);

typedef struct VerificationResult
{
    Error *Error;
    VerificationOutput *VerificationOutput;
} VerificationResult;

VerificationResult *alloc_VerificationResult();
void free_VerificationResult(VerificationResult *target);

#endif /* GOPENPGP_H */
