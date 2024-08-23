namespace Proton.Security.Interop;

internal unsafe interface IInteropArrayProvider
{
    InteropArray* GetInteropArray();
}
