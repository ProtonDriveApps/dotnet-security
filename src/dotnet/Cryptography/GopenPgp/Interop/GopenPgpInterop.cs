using Proton.Security.Interop;
using Proton.Security.InteropServices;

namespace Proton.Security.Cryptography.GopenPgp.Interop;

[SuppressUnmanagedCodeSecurity]
internal static class GopenPgpInterop
{
    private const string DllName = "ProtonSecurity";

    static GopenPgpInterop()
    {
        GoInteropEnvironment.EnsureInitialized();
    }

    [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
    public static extern InteropArrayResultHandle GeneratePrivateKey(
        [MarshalAs(UnmanagedType.LPUTF8Str)] string name,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string email,
        in InteropArray passphrase,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string keyType,
        int bits,
        long timestampSeconds);

    [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
    public static extern SessionKeyResultHandle GenerateSessionKey();

    [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
    public static extern void ReleaseSessionKeyResultMemory(IntPtr pointer);

    [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
    public static extern KeyPacketGenerationResultHandle GenerateKeyPacket(InteropKey publicKey);

    [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
    public static extern void ReleaseKeyPacketGenerationResultMemory(IntPtr pointer);

    [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
    public static extern InteropArrayResultHandle GenerateRandomToken(int size);

    [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
    public static extern InteropArrayResultHandle UnlockPrivateKey(in InteropArray privateKeyData, bool isArmored, in InteropArray passphrase);

    [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
    public static extern EncryptionResultHandle Encrypt(
        InteropEncryptionInput encryptionInput,
        InteropSignatureInput? signatureInput,
        long timestampSeconds,
        bool includeSessionKeyInResult);

    [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
    public static extern void ReleaseEncryptionResultMemory(IntPtr pointer);

    [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
    public static extern InteropArrayResultHandle Sign(
        in InteropArray plainData,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string? name,
        InteropSignatureInput signatureInput,
        long timestampSeconds);

    [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
    public static extern DecryptionResultHandle Decrypt(
        InteropDecryptionInput decryptionInput,
        InteropVerificationInput? verificationInput,
        bool includeSessionKeyInResult);

    [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
    public static extern void ReleaseDecryptionResultMemory(IntPtr pointer);

    [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
    public static extern InteropArrayResultHandle EncryptSessionKey(in InteropSessionKey sessionKey, IntPtr publicKey, in InteropArray password);

    [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
    public static extern InteropArrayResultHandle EncryptSessionKey(in InteropSessionKey sessionKey, InteropKey publicKey, IntPtr password);

    [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
    public static extern SessionKeyResultHandle DecryptSessionKey(
        IntPtr privateKeys,
        int privateKeyCount,
        IntPtr password,
        InteropArray keyPacket);

    [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
    public static extern VerificationResultHandle Verify(in InteropArray data, InteropVerificationInput verificationInput);

    [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
    public static extern void ReleaseVerificationResultMemory(IntPtr pointer);

    [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
    public static extern bool TestSessionKey(in InteropSessionKey sessionKey, in InteropArray dataPacketPrefix, in InteropArray expectedPlainDataPrefix);
}
