namespace Proton.Security.Cryptography.GopenPgp.Interop;

[StructLayout(LayoutKind.Sequential)]
internal unsafe struct InteropVerificationOutput
{
    public VerificationVerdict Code;

    public readonly void* Message;

    public string GetMessage()
    {
        return Marshal.PtrToStringUTF8(new IntPtr(Message)) ?? string.Empty;
    }
}
