namespace Proton.Security.InteropServices;

internal static class StringExtensions
{
    public static unsafe void* ToPointer(this string str, Action<IDisposable> registerDisposableAction)
    {
        Memory<byte> bytes = Encoding.UTF8.GetBytes(str);
        var handle = bytes.Pin();
        registerDisposableAction.Invoke(handle);
        return handle.Pointer;
    }
}
