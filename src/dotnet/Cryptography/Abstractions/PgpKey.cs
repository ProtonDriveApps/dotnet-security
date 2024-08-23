namespace Proton.Security.Cryptography.Abstractions;

public abstract class PgpKey
{
    protected PgpKey(ReadOnlyMemory<byte> data, bool dataIsArmored)
    {
        Data = data;
        DataIsArmored = dataIsArmored;
    }

    internal ReadOnlyMemory<byte> Data { get; }
    internal bool DataIsArmored { get; }

    public override string ToString()
    {
        if (!DataIsArmored)
        {
            // TODO: if one day we do create keys from unarmored data, we'll need to call GopenPGP to encode
            throw new NotSupportedException();
        }

        return Encoding.ASCII.GetString(Data.Span);
    }
}
