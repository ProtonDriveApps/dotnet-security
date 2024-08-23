using Proton.Security.Interop;

namespace Proton.Security.InteropServices;

internal static class SecureStringExtensions
{
    public static unsafe Disposable<InteropArray> ToInteropArray(this SecureString secureString)
    {
        var maxResultLength = Encoding.UTF8.GetMaxByteCount(secureString.Length);

        IntPtr binaryStringPointer = IntPtr.Zero;
        IntPtr result = IntPtr.Zero;

        try
        {
            result = Marshal.AllocHGlobal(maxResultLength);

            int resultLength;

            try
            {
                binaryStringPointer = Marshal.SecureStringToGlobalAllocUnicode(secureString);

                var binaryStringSpan = new ReadOnlySpan<char>(binaryStringPointer.ToPointer(), secureString.Length);
                var resultSpan = new Span<byte>(result.ToPointer(), maxResultLength);

                resultLength = Encoding.UTF8.GetBytes(binaryStringSpan, resultSpan);
            }
            finally
            {
                if (binaryStringPointer != IntPtr.Zero)
                {
                    Marshal.ZeroFreeGlobalAllocUnicode(binaryStringPointer);
                }
            }

            return new Disposable<InteropArray>(
                new InteropArray { Pointer = result.ToPointer(), Length = resultLength },
                () => ZeroFreeGlobalAlloc(result, resultLength));
        }
        catch
        {
            if (result != IntPtr.Zero)
            {
                ZeroFreeGlobalAlloc(result, maxResultLength);
            }

            throw;
        }
    }

    public static Stream ToStream(this SecureString secureString)
    {
        return new InteropArrayStream(secureString.ToInteropArray());
    }

    public static IntPtr ToInteropArrayPointer(this SecureString secure, Action<IDisposable> registerDisposableAction)
    {
        var interopArray = secure.ToInteropArray();
        registerDisposableAction.Invoke(interopArray);
        return Marshaller.AllocateAndMarshal(interopArray.Value, registerDisposableAction);
    }

    private static unsafe void ZeroFreeGlobalAlloc(IntPtr pointer, int length)
    {
        new Span<byte>(pointer.ToPointer(), length).Clear();
        Marshal.FreeHGlobal(pointer);
    }

    private sealed unsafe class InteropArrayStream : UnmanagedMemoryStream
    {
        private readonly Disposable<InteropArray> _interopArray;

        public InteropArrayStream(Disposable<InteropArray> interopArray)
            : base((byte*)interopArray.Value.Pointer, interopArray.Value.Length)
        {
            _interopArray = interopArray;
        }

        protected override void Dispose(bool disposing)
        {
            base.Dispose(disposing);

            if (disposing)
            {
                _interopArray.Dispose();
            }
        }
    }
}
