namespace Proton.Security.Cryptography.GopenPgp.Interop;

[StructLayout(LayoutKind.Sequential)]
internal readonly unsafe struct InteropError
{
    public readonly InteropErrorType Type;

    public readonly void* Message;

    public string? GetMessage()
    {
        return Message is not null ? Marshal.PtrToStringUTF8(new IntPtr(Message)) : default;
    }
}
