using Proton.Security.Interop;
using Proton.Security.InteropServices;

namespace Proton.Security;

public sealed class PasswordHasher : IPasswordHasher
{
    static PasswordHasher()
    {
        GoInteropEnvironment.EnsureInitialized();
    }

    public ReadOnlyMemory<byte> Hash(SecureString password, ReadOnlySpan<byte> salt)
    {
        InteropArrayResultHandle interopResultHandle;
        using (var passwordArray = password.ToInteropArray())
        {
            interopResultHandle = SrpInterop.MailboxPassword(passwordArray.Value, MemoryMarshal.GetReference(salt), salt.Length);
        }

        using (interopResultHandle)
        {
            return interopResultHandle.GetBytes((_, message) => new PasswordHashingException(message));
        }
    }
}
