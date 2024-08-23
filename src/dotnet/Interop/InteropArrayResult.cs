using Proton.Security.Cryptography.GopenPgp.Interop;

namespace Proton.Security.Interop;

[StructLayout(LayoutKind.Sequential)]
internal readonly unsafe struct InteropArrayResult : IErrorProvider, IInteropArrayProvider
{
    public readonly InteropError* Error;
    public readonly InteropArray* Array;

    public InteropError* GetError() => Error;
    public InteropArray* GetInteropArray() => Array;
}
