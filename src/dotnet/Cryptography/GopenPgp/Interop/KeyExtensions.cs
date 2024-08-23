using Proton.Security.Cryptography.Abstractions;
using Proton.Security.InteropServices;

namespace Proton.Security.Cryptography.GopenPgp.Interop;

internal static class KeyExtensions
{
    public static Disposable<InteropKey> ToInterop(this PublicPgpKey key)
    {
        var disposables = new List<IDisposable>(1);
        var interopKey = ConvertToInterop(key, (_, _) => new InteropKey(), disposables.Add);
        return new Disposable<InteropKey>(interopKey, disposables);
    }

    public static Disposable<InteropSessionKey> ToInterop(this PgpSessionKey key)
    {
        var disposables = new List<IDisposable>(2);
        var interopKey = ConvertToInterop(key, disposables.Add);
        return new Disposable<InteropSessionKey>(interopKey, disposables);
    }

    public static IntPtr ToInteropDisposablePointer(this PublicPgpKey? key, Action<IDisposable> registerDisposableAction)
    {
        if (key == null)
        {
            return IntPtr.Zero;
        }

        var interopKey = ConvertToInterop(key, (_, _) => new InteropKey(), registerDisposableAction);
        return Marshaller.AllocateAndMarshal(interopKey, registerDisposableAction);
    }

    public static IntPtr ToInteropDisposablePointer(this PrivatePgpKey key, Action<IDisposable> registerDisposableAction)
    {
        var interopKey = ConvertToInterop(key, CreateInteropPrivateKey, registerDisposableAction);
        return Marshaller.AllocateAndMarshal(interopKey, registerDisposableAction);
    }

    public static IntPtr ToInteropDisposablePointer(this IReadOnlyCollection<PublicPgpKey> keys, Action<IDisposable> registerDisposableAction)
    {
        return keys.ToInteropDisposablePointer((_, _) => new InteropKey(), registerDisposableAction);
    }

    public static IntPtr ToInteropDisposablePointer(this IReadOnlyCollection<PrivatePgpKey> keys, Action<IDisposable> registerDisposableAction)
    {
        return keys.ToInteropDisposablePointer(CreateInteropPrivateKey, registerDisposableAction);
    }

    public static IntPtr ToInteropDisposablePointer(this PgpSessionKey? key, Action<IDisposable> registerDisposableAction)
    {
        if (key == null)
        {
            return IntPtr.Zero;
        }

        var interopKey = ConvertToInterop(key, registerDisposableAction);
        return Marshaller.AllocateAndMarshal(interopKey, registerDisposableAction);
    }

    private static IntPtr ToInteropDisposablePointer<T, TInterop>(
        this IReadOnlyCollection<T> keys,
        Func<T, Action<IDisposable>, TInterop> interopKeyFactory,
        Action<IDisposable> registerDisposableAction)
        where T : PgpKey
        where TInterop : InteropKey
    {
        var result = Marshaller.AllocateAndMarshalByValArray(
            keys.Select(key => ConvertToInterop(key, interopKeyFactory, registerDisposableAction)),
            registerDisposableAction);

        return result;
    }

    private static TInterop ConvertToInterop<T, TInterop>(
        T key,
        Func<T, Action<IDisposable>, TInterop> interopKeyFactory,
        Action<IDisposable> registerDisposableAction)
        where T : PgpKey
        where TInterop : InteropKey
    {
        var interopKey = interopKeyFactory.Invoke(key, registerDisposableAction);

        interopKey.Data = key.Data.ToInteropArray(registerDisposableAction);
        interopKey.IsArmored = key.DataIsArmored;

        return interopKey;
    }

    private static unsafe InteropSessionKey ConvertToInterop(PgpSessionKey key, Action<IDisposable> registerDisposableAction)
    {
        return new()
        {
            Data = key.Data.ToInteropArray(registerDisposableAction),
            AlgorithmId = key.AlgorithmId.ToPointer(registerDisposableAction)
        };
    }

    private static InteropPrivateKey CreateInteropPrivateKey(PrivatePgpKey privateKey, Action<IDisposable> registerDisposableAction)
    {
        return new() { Passphrase = privateKey.Passphrase.ToInteropArray(registerDisposableAction) };
    }
}
