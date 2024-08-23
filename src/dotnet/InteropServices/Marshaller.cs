namespace Proton.Security.InteropServices;

internal static class Marshaller
{
    public static IntPtr AllocateAndMarshal<T>(in T structure, Action<IDisposable> registerDisposableAction)
        where T : notnull
    {
        var pointer = Marshal.AllocHGlobal(Size<T>.Value);

#pragma warning disable CA2000 // Dispose objects before losing scope // Disposable is added to collection of objects that will be disposed
        registerDisposableAction.Invoke(pointer.AsSafeHandle(Marshal.FreeHGlobal));
#pragma warning restore CA2000 // Dispose objects before losing scope

        Marshal.StructureToPtr(structure, pointer, false);
        return pointer;
    }

    public static IntPtr AllocateAndMarshalByRefArray<T>(IReadOnlyCollection<T> source, Action<IDisposable> registerDisposableAction)
        where T : notnull
    {
        return AllocateAndMarshalArray(source, registerDisposableAction, byValue: false);
    }

    public static IntPtr AllocateAndMarshalByValArray<T>(IReadOnlyCollection<T> source, Action<IDisposable> registerDisposableAction)
        where T : notnull
    {
        return AllocateAndMarshalArray(source, registerDisposableAction, byValue: true);
    }

    private static IntPtr AllocateAndMarshalArray<T>(IReadOnlyCollection<T> source, Action<IDisposable> registerDisposableAction, bool byValue)
        where T : notnull
    {
        var arrayPointer = Marshal.AllocHGlobal(source.Count * (byValue ? Size<T>.Value : IntPtr.Size));

#pragma warning disable CA2000 // Dispose objects before losing scope // Disposable is added to collection of objects that will be disposed
        registerDisposableAction.Invoke(arrayPointer.AsSafeHandle(Marshal.FreeHGlobal));
#pragma warning restore CA2000 // Dispose objects before losing scope

        if (byValue)
        {
            IntPtr currentPointer = arrayPointer;
            foreach (var item in source)
            {
                Marshal.StructureToPtr(item, currentPointer, false);
                currentPointer += Size<T>.Value;
            }
        }
        else
        {
            var i = 0;
            foreach (var item in source)
            {
                var itemPointer = AllocateAndMarshal(item, registerDisposableAction);
                Marshal.WriteIntPtr(arrayPointer, i++, itemPointer);
            }
        }

        return arrayPointer;
    }

    private static class Size<T>
    {
        // ReSharper disable once StaticMemberInGenericType
        // This is intentional, we do want the possibility of different values per type argument
        private static int? _value;

        public static int Value => _value ??= Marshal.SizeOf<T>();
    }
}
