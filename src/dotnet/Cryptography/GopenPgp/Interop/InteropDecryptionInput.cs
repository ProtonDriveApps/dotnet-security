using Proton.Security.Interop;

namespace Proton.Security.Cryptography.GopenPgp.Interop;

[StructLayout(LayoutKind.Sequential)]
[SuppressMessage("StyleCop.CSharp.MaintainabilityRules", "SA1401:Fields should be private", Justification = "Required for interop marshaling")]
internal sealed class InteropDecryptionInput
{
    public IntPtr PrivateKeys;
    public int PrivateKeysLength;
    public IntPtr Password;
    public InteropArray Message;
    public bool MessageIsArmored;
}
