using Proton.Security.Cryptography.GopenPgp.Interop;
using Proton.Security.Interop;

namespace Proton.Security.InteropServices;

internal static class StructureHandleExtensions
{
    public static T ToStructure<T>(this StructureHandle<T> structureHandle, Func<InteropErrorType, string?, Exception> exceptionFactory)
        where T : struct, IErrorProvider
    {
        var structure = structureHandle.ToStructure();

        unsafe
        {
            var error = structure.GetError();

            if (error is not null)
            {
                throw exceptionFactory.Invoke(error->Type, error->GetMessage());
            }
        }

        return structure;
    }

    public static byte[] GetBytes<T>(this StructureHandle<T> structureHandle, Func<InteropErrorType, string?, Exception> exceptionFactory)
        where T : struct, IErrorProvider, IInteropArrayProvider
    {
        var structure = structureHandle.ToStructure(exceptionFactory);

        unsafe
        {
            return structure.GetInteropArray()->ToArray();
        }
    }
}
