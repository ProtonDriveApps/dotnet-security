namespace Proton.Security.Interop;

[StructLayout(LayoutKind.Sequential)]
internal readonly unsafe struct InteropProofGenerationResult
{
    [MarshalAs(UnmanagedType.LPUTF8Str)]
    public readonly string Error;
    public readonly InteropArray* ClientProof;
    public readonly InteropArray* ClientEphemeral;
    public readonly InteropArray* ExpectedServerProof;
}
