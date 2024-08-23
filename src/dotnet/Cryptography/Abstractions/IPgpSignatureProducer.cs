namespace Proton.Security.Cryptography.Abstractions;

public interface IPgpSignatureProducer
{
    Stream GetSignatureStream(PlainDataSource plainDataSource, DetachedSignatureParameters detachedSignatureParameters);
}
