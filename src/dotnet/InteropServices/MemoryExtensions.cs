using Proton.Security.Interop;

namespace Proton.Security.InteropServices;

internal static class MemoryExtensions
{
    public static unsafe void* ToPointer<T>(this ReadOnlyMemory<T> memory, Action<IDisposable> registerDisposableAction)
    {
        var memoryHandle = memory.Pin();
        registerDisposableAction.Invoke(memoryHandle);
        return memoryHandle.Pointer;
    }

    public static unsafe InteropArray ToInteropArray<T>(this ReadOnlyMemory<T> memory, Action<IDisposable> registerDisposableAction)
    {
        var memoryHandle = memory.Pin();
        registerDisposableAction.Invoke(memoryHandle);
        return new InteropArray { Pointer = memoryHandle.Pointer, Length = memory.Length };
    }

    public static unsafe Disposable<InteropArray> ToInteropArray<T>(this ReadOnlyMemory<T> memory)
    {
        var memoryHandle = memory.Pin();
        return new Disposable<InteropArray>(new InteropArray { Pointer = memoryHandle.Pointer, Length = memory.Length }, memoryHandle);
    }
}
