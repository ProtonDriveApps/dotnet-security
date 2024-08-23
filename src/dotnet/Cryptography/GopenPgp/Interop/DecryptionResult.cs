using Proton.Security.Interop;

namespace Proton.Security.Cryptography.GopenPgp.Interop;

[StructLayout(LayoutKind.Sequential)]
internal readonly unsafe struct DecryptionResult : IErrorProvider, IInteropArrayProvider
{
    public readonly InteropError* Error;
    public readonly InteropDecryptionOutput* DecryptionOutput;
    public readonly InteropVerificationOutput* VerificationOutput;

    InteropError* IErrorProvider.GetError() => Error;
    InteropArray* IInteropArrayProvider.GetInteropArray() => &DecryptionOutput->PlainData;
}
