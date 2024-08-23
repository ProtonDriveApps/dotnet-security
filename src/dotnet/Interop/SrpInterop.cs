using Proton.Security.InteropServices;

namespace Proton.Security.Interop;

internal static class SrpInterop
{
    private const string DllName = "ProtonSecurity";

    static SrpInterop()
    {
        GoInteropEnvironment.EnsureInitialized();
    }

    [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
    public static extern InteropArrayResultHandle GenerateChallenge(
        in InteropArray modulusBytes,
        in InteropArray verifier,
        in InteropArray secretBytes,
        int bitLength);

    [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
    public static extern InteropArrayResultHandle VerifyClientProof(
        in InteropArray modulusBytes,
        in InteropArray verifier,
        in InteropArray secretBytes,
        in InteropArray clientProofBytes,
        in InteropArray clientEphemeralBytes,
        int bitLength);

    [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
    public static extern InteropArrayResultHandle GenerateVerifier(
        in InteropArray password,
        in InteropArray salt,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string signedModulus,
        int bitLength);

    [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
    public static extern SrpProofGenerationResultHandle GenerateProofs(
        int version,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string username,
        in InteropArray password,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string salt,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string signedModulus,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string serverEphemeral,
        int bitLength);

    [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
    public static extern void ReleaseProofGenerationResultMemory(IntPtr pointer);

    [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
    public static extern InteropArrayResultHandle MailboxPassword(in InteropArray password, in byte salt, int saltLength);
}
