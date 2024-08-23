using System.Numerics;
using Proton.Security.Interop;
using Proton.Security.InteropServices;

namespace Proton.Security;

public sealed class SrpServer
{
    private const int Version = 4;

    private readonly ReadOnlyMemory<byte> _modulusBytes;
    private readonly ReadOnlyMemory<byte> _verifier;
    private readonly ReadOnlyMemory<byte> _secretBytes;
    private readonly int _bitLength;

    static SrpServer()
    {
        GoInteropEnvironment.EnsureInitialized();
    }

    internal SrpServer(ReadOnlyMemory<byte> modulusBytes, ReadOnlyMemory<byte> verifier, ReadOnlyMemory<byte> secretBytes, int bitLength)
    {
        _modulusBytes = modulusBytes;
        _verifier = verifier;
        _secretBytes = secretBytes;
        _bitLength = bitLength;
    }

    public static SrpServer Create(ReadOnlyMemory<byte> modulusBytes, ReadOnlyMemory<byte> verifier, int bitLength)
    {
        var modulus = new BigInteger(modulusBytes.Span);
        var modulusMinusOne = modulus - 1;
        var secretByteCount = (modulusMinusOne.GetBitLength() + 7) / 8;
        var secretBytes = new byte[secretByteCount];

        using var randomNumberGenerator = RandomNumberGenerator.Create();
        BigInteger secret;
        do
        {
            randomNumberGenerator.GetBytes(secretBytes);
            secret = new BigInteger(secretBytes);
        }
        while (secret >= bitLength * 2);

        return new SrpServer(modulusBytes, verifier, secretBytes, bitLength);
    }

    public SrpServerGeneratedChallenge GenerateChallenge()
    {
        InteropArrayResultHandle? interopResultHandle;
        using (var modulusArray = _modulusBytes.ToInteropArray())
        using (var verifierArray = _verifier.ToInteropArray())
        using (var secretArray = _secretBytes.ToInteropArray())
        {
            interopResultHandle = SrpInterop.GenerateChallenge(modulusArray.Value, verifierArray.Value, secretArray.Value, _bitLength);
        }

        using (interopResultHandle)
        {
            return new SrpServerGeneratedChallenge(Version, interopResultHandle.GetBytes((_, message) => new SrpException(message)));
        }
    }

    public ReadOnlyMemory<byte> VerifyAndCalculateResponse(ReadOnlyMemory<byte> clientProof, ReadOnlyMemory<byte> ephemeral)
    {
        InteropArrayResultHandle? interopResultHandle;
        using (var modulusArray = _modulusBytes.ToInteropArray())
        using (var verifierArray = _verifier.ToInteropArray())
        using (var secretArray = _secretBytes.ToInteropArray())
        using (var clientProofArray = clientProof.ToInteropArray())
        using (var ephemeralArray = ephemeral.ToInteropArray())
        {
            interopResultHandle = SrpInterop.VerifyClientProof(
                modulusArray.Value,
                verifierArray.Value,
                secretArray.Value,
                clientProofArray.Value,
                ephemeralArray.Value,
                _bitLength);
        }

        using (interopResultHandle)
        {
            return interopResultHandle.GetBytes((_, message) => new SrpException(message));
        }
    }
}
