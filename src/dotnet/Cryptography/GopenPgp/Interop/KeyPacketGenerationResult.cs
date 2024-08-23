using Proton.Security.Interop;

namespace Proton.Security.Cryptography.GopenPgp.Interop;

[StructLayout(LayoutKind.Sequential)]
internal readonly unsafe struct KeyPacketGenerationResult : IErrorProvider
{
    public readonly InteropError* Error;
    public readonly InteropSessionKey* SessionKey;
    public readonly InteropArray* KeyPacket;

    InteropError* IErrorProvider.GetError() => Error;
}
