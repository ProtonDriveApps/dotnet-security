using Proton.Security.Cryptography.GopenPgp.Interop;

namespace Proton.Security.Interop;

internal unsafe interface IErrorProvider
{
    InteropError* GetError();
}
