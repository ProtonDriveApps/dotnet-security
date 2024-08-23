namespace Proton.Security.Cryptography.GopenPgp.Interop;

[StructLayout(LayoutKind.Sequential)]
internal readonly struct InteropSignatureDetachmentInput
{
    public InteropSignatureDetachmentInput(IntPtr publicKeyForEncryption, bool isArmored)
    {
        PublicKeyForEncryption = publicKeyForEncryption;
        IsArmored = isArmored;
    }

    public IntPtr PublicKeyForEncryption { get; }
    public bool IsArmored { get; }
}
