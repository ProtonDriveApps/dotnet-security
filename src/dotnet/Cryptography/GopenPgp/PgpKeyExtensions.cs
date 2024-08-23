using Proton.Security.Cryptography.Abstractions;
using Proton.Security.Cryptography.GopenPgp.Interop;
using Proton.Security.Interop;

namespace Proton.Security.Cryptography.GopenPgp;

public static class PgpKeyExtensions
{
    public static unsafe bool IsValid(this PrivatePgpKey privateKey)
    {
        InteropArrayResultHandle? interopResultHandle;
        fixed (byte* privateKeyDataPointer = &MemoryMarshal.GetReference(privateKey.Data.Span))
        {
            fixed (byte* passphrasePointer = &MemoryMarshal.GetReference(privateKey.Passphrase.Span))
            {
                var interopPrivateKeyData = new InteropArray { Pointer = privateKeyDataPointer, Length = privateKey.Data.Length };
                var interopPassphrase = new InteropArray { Pointer = passphrasePointer, Length = privateKey.Passphrase.Length };

                interopResultHandle = GopenPgpInterop.UnlockPrivateKey(interopPrivateKeyData, true, interopPassphrase);
            }
        }

        using (interopResultHandle)
        {
            var result = interopResultHandle.ToStructure();

            if (result.Error is not null)
            {
                if (result.Error->Type != InteropErrorType.InvalidPassphrase)
                {
                    throw new CryptographicException(result.Error->GetMessage());
                }

                return false;
            }
        }

        return true;
    }

    public static bool MatchesDataPacketPrefix(
        this PgpSessionKey sessionKey,
        ReadOnlySpan<byte> dataPacketPrefix,
        ReadOnlySpan<byte> expectedPlainDataPrefix)
    {
        using var interopSessionKey = sessionKey.ToInterop();

        unsafe
        {
            fixed (byte* dataPacketPrefixPointer = dataPacketPrefix)
            fixed (byte* expectedPlainDataPrefixPointer = expectedPlainDataPrefix)
            {
                var interopDataPacketPrefix = new InteropArray { Pointer = dataPacketPrefixPointer, Length = dataPacketPrefix.Length };
                var interopExpectedPlainDataPrefix = new InteropArray { Pointer = expectedPlainDataPrefixPointer, Length = expectedPlainDataPrefix.Length };

                return GopenPgpInterop.TestSessionKey(interopSessionKey.Value, interopDataPacketPrefix, interopExpectedPlainDataPrefix);
            }
        }
    }
}
