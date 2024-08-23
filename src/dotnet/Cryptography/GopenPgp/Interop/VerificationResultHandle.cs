using Proton.Security.Interop;

namespace Proton.Security.Cryptography.GopenPgp.Interop;

internal sealed class VerificationResultHandle : StructureHandle<VerificationResult>
{
    protected override bool ReleaseHandle()
    {
        GopenPgpInterop.ReleaseVerificationResultMemory(handle);
        return true;
    }
}
