namespace Proton.Security.Cryptography.Abstractions;

public record DecryptingAndVerifyingStreamWithSessionKeyProvisionResult(
        Stream DecryptionStream,
        Task<VerificationVerdict> VerificationTask,
        Task<PgpSessionKey> SessionKeyTask)
    : DecryptingAndVerifyingStreamProvisionResult(DecryptionStream, VerificationTask);
