using Proton.Security.Interop;

namespace Proton.Security.Cryptography.GopenPgp.Interop;

[StructLayout(LayoutKind.Sequential)]
internal readonly unsafe struct EncryptionResult : IErrorProvider, IInteropArrayProvider
{
    public readonly InteropError* Error;
    public readonly InteropArray* EncryptedMessage;
    public readonly InteropSignature* DetachedSignature;
    public readonly InteropSessionKey* SessionKey;

    InteropError* IErrorProvider.GetError() => Error;
    InteropArray* IInteropArrayProvider.GetInteropArray() => EncryptedMessage;
}
