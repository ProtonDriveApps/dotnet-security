using Proton.Security.Cryptography.Abstractions;
using Proton.Security.Interop;
using Proton.Security.InteropServices;

namespace Proton.Security.Cryptography.GopenPgp.Interop;

[StructLayout(LayoutKind.Sequential)]
[SuppressMessage("StyleCop.CSharp.MaintainabilityRules", "SA1401:Fields should be private", Justification = "Required for interop marshaling")]
internal sealed class InteropEncryptionInput
{
    public IntPtr PublicKey;
    public IntPtr SessionKey;
    public IntPtr Password;
    public InteropArray PlainData;
    public bool MessageMustBeArmored;
    public bool MessageMustBeCompressed;
    public IntPtr Name;

    public static unsafe Disposable<InteropEncryptionInput> Create(
        PublicPgpKey? publicKey,
        PgpSessionKey? sessionKey,
        SecureString? password,
        ReadOnlyMemory<byte> plainData,
        PgpArmoring armoring,
        PgpCompression compression,
        string? name = default)
    {
        var disposables = new List<IDisposable>(7);
        try
        {
            var encryptionInput = new InteropEncryptionInput
            {
                PublicKey = publicKey.ToInteropDisposablePointer(disposables.Add),
                SessionKey = sessionKey.ToInteropDisposablePointer(disposables.Add),
                Password = password?.ToInteropArrayPointer(disposables.Add) ?? IntPtr.Zero,
                PlainData = new InteropArray { Pointer = plainData.ToPointer(disposables.Add), Length = plainData.Length },
                MessageMustBeArmored = armoring == PgpArmoring.Ascii,
                MessageMustBeCompressed = compression == PgpCompression.Deflate,
                Name = name is not null ? new IntPtr(name.ToPointer(disposables.Add)) : IntPtr.Zero,
            };

            return new Disposable<InteropEncryptionInput>(encryptionInput, disposables);
        }
        catch
        {
            // TODO: wrap the unmanaged pointers in an object that has a finalizer, such as SafeHandle
            foreach (var disposable in disposables)
            {
                disposable.Dispose();
            }

            throw;
        }
    }
}
