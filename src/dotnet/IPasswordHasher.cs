namespace Proton.Security;

public interface IPasswordHasher
{
    ReadOnlyMemory<byte> Hash(SecureString password, ReadOnlySpan<byte> salt);
}
