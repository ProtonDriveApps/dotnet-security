using System.Diagnostics.Contracts;
using System.Runtime.CompilerServices;

namespace Proton.Security.Interop;

[StructLayout(LayoutKind.Sequential)]
internal unsafe struct InteropArray
{
    public void* Pointer;
    public int Length;

    [Pure]
    public byte[] ToArray()
    {
        var result = new byte[Length];

        fixed (void* resultPointer = result)
        {
            Unsafe.CopyBlock(resultPointer, Pointer, (uint)Length);
        }

        return result;
    }

    public override string ToString()
    {
        return Encoding.UTF8.GetString((byte*)Pointer, Length);
    }

    public Stream AsByteStream()
    {
        return new UnmanagedMemoryStream((byte*)Pointer, Length);
    }
}
