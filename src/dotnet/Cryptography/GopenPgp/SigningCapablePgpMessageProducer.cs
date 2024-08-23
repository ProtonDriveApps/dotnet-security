using Proton.Security.Cryptography.Abstractions;
using Proton.Security.Cryptography.GopenPgp.Interop;

namespace Proton.Security.Cryptography.GopenPgp;

public sealed class SigningCapablePgpMessageProducer : KeyBasedPgpMessageProducer, ISigningCapablePgpMessageProducer
{
    private readonly PrivatePgpKey _signatureKey;
    private readonly PublicPgpKey _signatureEncryptionPublicKey;

    public SigningCapablePgpMessageProducer(PublicPgpKey publicKey, PrivatePgpKey signatureKey, Func<DateTimeOffset> getTimestampFunction)
        : this(publicKey, signatureKey, publicKey, getTimestampFunction)
    {
    }

    public SigningCapablePgpMessageProducer(
        PublicPgpKey publicKey,
        PgpSessionKey sessionKey,
        PrivatePgpKey signatureKey,
        Func<DateTimeOffset> getTimestampFunction)
        : this(publicKey, sessionKey, signatureKey, publicKey, getTimestampFunction)
    {
    }

    public SigningCapablePgpMessageProducer(
        PublicPgpKey publicKey,
        PrivatePgpKey signatureKey,
        PublicPgpKey signatureEncryptionPublicKey,
        Func<DateTimeOffset> getTimestampFunction)
        : base(publicKey, getTimestampFunction)
    {
        _signatureKey = signatureKey;
        _signatureEncryptionPublicKey = signatureEncryptionPublicKey;
    }

    public SigningCapablePgpMessageProducer(
        PublicPgpKey publicKey,
        PgpSessionKey sessionKey,
        PrivatePgpKey signatureKey,
        PublicPgpKey signatureEncryptionPublicKey,
        Func<DateTimeOffset> getTimestampFunction)
        : base(publicKey, sessionKey, getTimestampFunction)
    {
        _signatureKey = signatureKey;
        _signatureEncryptionPublicKey = signatureEncryptionPublicKey;
    }

    public Stream GetEncryptingAndSigningStream(
        PlainDataSource plainDataSource,
        PgpArmoring messageArmoring = PgpArmoring.None,
        PgpCompression compression = PgpCompression.None)
    {
        return new EncryptingStream(
            (plainData, name) => InteropEncryptionInput.Create(PublicKey, SessionKey, null, plainData, messageArmoring, compression, name),
            () => InteropSignatureInput.Create(_signatureKey, null),
            plainDataSource,
            GetTimestampFunction);
    }

    public (Stream EncryptingStream, Stream SignatureStream) GetEncryptingAndSignatureStreams(
        PlainDataSource plainDataSource,
        DetachedSignatureParameters detachedSignatureParameters,
        PgpArmoring messageArmoring = PgpArmoring.None,
        PgpCompression compression = PgpCompression.None)
    {
        return EncryptingStream.CreateWithSignatureStream(
            (plainData, name) => InteropEncryptionInput.Create(PublicKey, SessionKey, null, plainData, messageArmoring, compression, name),
            () => CreateInteropSignatureInput(detachedSignatureParameters),
            plainDataSource,
            GetTimestampFunction);
    }

    public (Stream EncryptingStream, Stream SignatureStream, Task<PgpSessionKey> SessionKey) GetEncryptingAndSignatureStreamsWithSessionKey(
        PlainDataSource plainDataSource,
        DetachedSignatureParameters detachedSignatureParameters,
        PgpArmoring messageArmoring = PgpArmoring.None,
        PgpCompression compression = PgpCompression.None)
    {
        var sessionKeyTaskCompletionSource = new TaskCompletionSource<PgpSessionKey>();
        var streams = EncryptingStream.CreateWithSignatureStream(
            (plainData, name) => InteropEncryptionInput.Create(PublicKey, SessionKey, null, plainData, messageArmoring, compression, name),
            () => CreateInteropSignatureInput(detachedSignatureParameters),
            plainDataSource,
            sessionKeyTaskCompletionSource.SetResult,
            GetTimestampFunction);
        return (streams.EncryptingStream, streams.SignatureStream, sessionKeyTaskCompletionSource.Task);
    }

    public Stream GetSignatureStream(PlainDataSource plainDataSource, DetachedSignatureParameters detachedSignatureParameters)
    {
        return new SignatureStream(plainDataSource, () => CreateInteropSignatureInput(detachedSignatureParameters), GetTimestampFunction);
    }

    private Disposable<InteropSignatureInput> CreateInteropSignatureInput(DetachedSignatureParameters detachedSignatureParameters)
    {
        var publicKeyForSignatureEncryption = detachedSignatureParameters.Security == PgpSignatureSecurity.Encrypted
            ? _signatureEncryptionPublicKey
            : null;

        var mustArmor = detachedSignatureParameters.Armoring == PgpArmoring.Ascii;

        return InteropSignatureInput.Create(_signatureKey, (publicKeyForSignatureEncryption, mustArmor));
    }
}
