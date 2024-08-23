using Proton.Security.Cryptography.Abstractions;
using Proton.Security.Cryptography.GopenPgp.Interop;
using Proton.Security.InteropServices;

namespace Proton.Security.Cryptography.GopenPgp;

public static class PgpGenerator
{
    public static PrivatePgpKey GeneratePrivateKey(
        string name,
        string emailAddress,
        ReadOnlyMemory<byte> passphrase,
        KeySpecification keySpecification,
        DateTimeOffset timestamp)
    {
        var keyTypeString = keySpecification.Type switch { KeyType.Rsa => "rsa", KeyType.X25519 => "x25519", _ => throw new NotSupportedException() };

        using var passphraseInteropArray = passphrase.ToInteropArray();

        using var interopResultHandle = GopenPgpInterop.GeneratePrivateKey(
            name,
            emailAddress,
            passphraseInteropArray.Value,
            keyTypeString,
            keySpecification.Bits ?? 0,
            timestamp.ToUnixTimeSeconds());

        var interopResult = interopResultHandle.ToStructure((_, message) => new CryptographicException(message));

        unsafe
        {
            return PrivatePgpKey.FromArmored(interopResult.Array->ToString(), passphrase);
        }
    }

    public static PgpSessionKey GenerateSessionKey()
    {
        using var interopResultHandle = GopenPgpInterop.GenerateSessionKey();

        var interopResult = interopResultHandle.ToStructure((_, message) => new CryptographicException(message));

        unsafe
        {
            return new PgpSessionKey(interopResult.SessionKey->Data.ToArray(), interopResult.SessionKey->GetAlgorithmId());
        }
    }

    public static (ReadOnlyMemory<byte> KeyPacket, PgpSessionKey SessionKey) GenerateKeyPacket(PublicPgpKey publicKey)
    {
        using var interopPublicKey = publicKey.ToInterop();
        using var interopResultHandle = GopenPgpInterop.GenerateKeyPacket(interopPublicKey.Value);

        var interopResult = interopResultHandle.ToStructure((_, message) => new CryptographicException(message));

        unsafe
        {
            var keyPacket = (ReadOnlyMemory<byte>)interopResult.KeyPacket->ToArray();

            var sessionKey = new PgpSessionKey(interopResult.SessionKey->Data.ToArray(), interopResult.SessionKey->GetAlgorithmId());

            return (keyPacket, sessionKey);
        }
    }

    public static byte[] GenerateRandomToken(int sizeInBytes)
    {
        using var interopResultHandle = GopenPgpInterop.GenerateRandomToken(sizeInBytes);

        return interopResultHandle.GetBytes((_, message) => new CryptographicException(message));
    }
}
