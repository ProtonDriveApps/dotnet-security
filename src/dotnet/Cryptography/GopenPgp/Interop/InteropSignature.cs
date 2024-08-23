using Proton.Security.Interop;

namespace Proton.Security.Cryptography.GopenPgp.Interop;

[StructLayout(LayoutKind.Sequential)]
internal struct InteropSignature
{
    public InteropArray Data;
    public bool IsEncrypted;
    public bool IsArmored;
}
