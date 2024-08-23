namespace Proton.Security.Cryptography.Abstractions;

public record DecryptingAndVerifyingStreamProvisionResult(Stream Stream, Task<VerificationVerdict> VerificationTask);
