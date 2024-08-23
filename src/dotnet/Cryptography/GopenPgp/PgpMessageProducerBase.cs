using Proton.Security.Cryptography.Abstractions;
using Proton.Security.Cryptography.GopenPgp.Interop;

namespace Proton.Security.Cryptography.GopenPgp;

public abstract class PgpMessageProducerBase : IPgpMessageProducer
{
    protected abstract PublicPgpKey? PublicKey { get; }

    protected abstract PgpSessionKey? SessionKey { get; }

    protected abstract SecureString? Password { get; }

    protected abstract Func<DateTimeOffset> GetTimestampFunction { get; }

    public Stream GetEncryptingStream(
        PlainDataSource plainDataSource,
        PgpArmoring outputArmoring = PgpArmoring.None,
        PgpCompression compression = PgpCompression.None)
    {
        return new EncryptingStream(
            (plainData, name) => InteropEncryptionInput.Create(PublicKey, SessionKey, Password, plainData, outputArmoring, compression, name),
            plainDataSource,
            GetTimestampFunction);
    }

    public (Stream Stream, Task<PgpSessionKey> SessionKey) GetEncryptingStreamWithSessionKey(
        PlainDataSource plainDataSource,
        PgpArmoring outputArmoring = PgpArmoring.None,
        PgpCompression compression = PgpCompression.None)
    {
        var sessionKeyTaskCompletionSource = new TaskCompletionSource<PgpSessionKey>();

        var stream = new EncryptingStream(
            (plainData, name) => InteropEncryptionInput.Create(PublicKey, SessionKey, Password, plainData, outputArmoring, compression, name),
            plainDataSource,
            sessionKeyTaskCompletionSource.SetResult,
            GetTimestampFunction);

        return (stream, sessionKeyTaskCompletionSource.Task);
    }
}
