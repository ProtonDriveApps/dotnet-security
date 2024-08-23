namespace Proton.Security.Cryptography.Abstractions;

public interface IPgpKeyPacketProducer
{
    ReadOnlyMemory<byte> GetKeyPacket(PublicPgpKey publicKey);
    ReadOnlyMemory<byte> GetKeyPacket(SecureString password);
}
