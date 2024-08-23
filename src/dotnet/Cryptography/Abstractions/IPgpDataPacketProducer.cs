namespace Proton.Security.Cryptography.Abstractions;

public interface IPgpDataPacketProducer
{
    Stream GetDataPacketStream(PlainDataSource plainDataSource);
}
