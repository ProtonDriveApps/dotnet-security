using Proton.Security.InteropServices;

namespace Proton.Security.Cryptography.GopenPgp;

public class PasswordBasedPgpDecrypter : PgpDecrypterBase
{
    private readonly SecureString _password;

    public PasswordBasedPgpDecrypter(SecureString password)
    {
        _password = password;
    }

    protected override int PrivateKeyCount => 0;

    protected override IntPtr GetPasswordPointer(Action<IDisposable> registerDisposableAction)
    {
        return _password.ToInteropArrayPointer(registerDisposableAction);
    }

    protected override IntPtr GetPrivateKeysPointer(Action<IDisposable> registerDisposableAction)
    {
        return IntPtr.Zero;
    }
}
