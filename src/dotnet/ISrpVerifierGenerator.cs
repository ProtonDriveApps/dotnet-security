namespace Proton.Security;

public interface ISrpVerifierGenerator
{
    ReadOnlyMemory<byte> Generate(SecureString password, ReadOnlyMemory<byte> salt, string signedModulus);
}
