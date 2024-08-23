using Proton.Security.Interop;

namespace Proton.Security.Cryptography.GopenPgp.Interop;

[StructLayout(LayoutKind.Sequential)]
internal readonly unsafe struct SessionKeyResult : IErrorProvider
{
    public readonly InteropError* Error;
    public readonly InteropSessionKey* SessionKey;

    InteropError* IErrorProvider.GetError() => Error;
}
