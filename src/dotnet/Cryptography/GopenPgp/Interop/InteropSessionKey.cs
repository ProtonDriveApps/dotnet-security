using Proton.Security.Interop;

namespace Proton.Security.Cryptography.GopenPgp.Interop;

[StructLayout(LayoutKind.Sequential)]
internal unsafe struct InteropSessionKey
{
    public void* AlgorithmId;

    public InteropArray Data;

    public string GetAlgorithmId()
    {
        return Marshal.PtrToStringUTF8(new IntPtr(AlgorithmId)) ?? string.Empty;
    }
}
