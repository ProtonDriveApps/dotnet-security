using Proton.Security.Cryptography.Abstractions;

namespace Proton.Security.Cryptography.GopenPgp;

public class KeyBasedPgpMessageProducer : PgpMessageProducerBase
{
    public KeyBasedPgpMessageProducer(PublicPgpKey publicKey, Func<DateTimeOffset> getTimestampFunction)
    {
        PublicKey = publicKey;
        GetTimestampFunction = getTimestampFunction;
    }

    public KeyBasedPgpMessageProducer(PublicPgpKey publicKey, PgpSessionKey sessionKey, Func<DateTimeOffset> getTimestampFunction)
        : this(publicKey, getTimestampFunction)
    {
        SessionKey = sessionKey;
    }

    protected override PublicPgpKey PublicKey { get; }

    protected override PgpSessionKey? SessionKey { get; }

    protected override SecureString? Password => null;

    protected override Func<DateTimeOffset> GetTimestampFunction { get; }
}
