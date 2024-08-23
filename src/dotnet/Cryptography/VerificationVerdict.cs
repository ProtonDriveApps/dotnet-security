namespace Proton.Security.Cryptography;

public enum VerificationVerdict
{
    ValidSignature = 0,
    NoSignature = 1,
    NoMatchingSignature = 2,
    InvalidSignature = 3
}
