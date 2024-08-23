using Proton.Security.Interop;

namespace Proton.Security.Cryptography.GopenPgp.Interop;

[StructLayout(LayoutKind.Sequential)]
internal readonly unsafe struct InteropDecryptionOutput
{
    public readonly InteropArray PlainData;
    public readonly InteropSessionKey* SessionKey;
}
