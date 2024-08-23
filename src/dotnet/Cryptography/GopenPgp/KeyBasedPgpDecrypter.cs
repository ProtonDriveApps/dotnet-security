using Proton.Security.Cryptography.Abstractions;
using Proton.Security.Cryptography.GopenPgp.Interop;

namespace Proton.Security.Cryptography.GopenPgp;

public class KeyBasedPgpDecrypter : PgpDecrypterBase
{
    private readonly IReadOnlyCollection<PrivatePgpKey> _privateKeys;

    public KeyBasedPgpDecrypter(IReadOnlyCollection<PrivatePgpKey> privateKeys)
    {
        _privateKeys = privateKeys;
    }

    protected override int PrivateKeyCount => _privateKeys.Count;

    protected override IntPtr GetPasswordPointer(Action<IDisposable> registerDisposableAction)
    {
        return IntPtr.Zero;
    }

    protected override IntPtr GetPrivateKeysPointer(Action<IDisposable> registerDisposableAction)
    {
        return _privateKeys.ToInteropDisposablePointer(registerDisposableAction);
    }
}
