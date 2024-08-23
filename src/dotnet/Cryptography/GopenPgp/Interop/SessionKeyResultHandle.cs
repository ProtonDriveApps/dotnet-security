using Proton.Security.Interop;

namespace Proton.Security.Cryptography.GopenPgp.Interop;

internal sealed class SessionKeyResultHandle : StructureHandle<SessionKeyResult>
{
    protected override bool ReleaseHandle()
    {
        GopenPgpInterop.ReleaseSessionKeyResultMemory(handle);
        return true;
    }
}
