namespace Proton.Security.Cryptography.Abstractions;

public interface IVerificationCapablePgpDecrypter : IPgpDecrypter
{
    DecryptingAndVerifyingStreamProvisionResult GetDecryptingAndVerifyingStream(PgpMessageSource messageSource);

    DecryptingAndVerifyingStreamWithSessionKeyProvisionResult GetDecryptingAndVerifyingStreamWithSessionKey(PgpMessageSource messageSource);

    DecryptingAndVerifyingStreamProvisionResult GetDecryptingAndVerifyingStream(PgpMessageSource messageSource, PgpSignatureSource detachedSignatureSource);

    DecryptingAndVerifyingStreamWithSessionKeyProvisionResult GetDecryptingAndVerifyingStreamWithSessionKey(
        PgpMessageSource messageSource,
        PgpSignatureSource detachedSignatureSource);

    DecryptingAndVerifyingStreamProvisionResult GetDecryptingAndVerifyingStream(
        PgpMessageSource messageSource,
        PgpMessageSource detachedSignatureMessageSource);

    DecryptingAndVerifyingStreamWithSessionKeyProvisionResult GetDecryptingAndVerifyingStreamWithSessionKey(
        PgpMessageSource messageSource,
        PgpMessageSource detachedSignatureMessageSource);

    Task<VerificationVerdict> VerifyAsync(ReadOnlyMemory<byte> plainData, PgpSignatureSource signatureSource, CancellationToken cancellationToken);
}
