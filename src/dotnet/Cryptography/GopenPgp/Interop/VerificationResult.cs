using Proton.Security.Interop;

namespace Proton.Security.Cryptography.GopenPgp.Interop;

[StructLayout(LayoutKind.Sequential)]
internal readonly unsafe struct VerificationResult : IErrorProvider
{
    public readonly InteropError* Error;
    public readonly InteropVerificationOutput* VerificationOutput;

    InteropError* IErrorProvider.GetError() => Error;
}
