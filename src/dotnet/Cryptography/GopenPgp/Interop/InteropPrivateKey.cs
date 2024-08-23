using Proton.Security.Interop;

namespace Proton.Security.Cryptography.GopenPgp.Interop;

[StructLayout(LayoutKind.Sequential)]
[SuppressMessage("StyleCop.CSharp.MaintainabilityRules", "SA1401:Fields should be private", Justification = "Required for interop marshaling")]
internal sealed class InteropPrivateKey : InteropKey
{
    public InteropArray Passphrase;
}
