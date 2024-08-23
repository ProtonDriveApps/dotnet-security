namespace Proton.Security.Cryptography.Abstractions;

public static class PgpDecrypterExtensions
{
    public static ReadOnlyMemory<byte> DecryptAndVerify(
        this IVerificationCapablePgpDecrypter decrypter,
        string armoredSignedMessage,
        out VerificationVerdict verificationVerdict)
    {
        var result = Decrypt(
            armoredSignedMessage,
            decrypter.GetDecryptingAndVerifyingStream,
            streamProvisionResult => streamProvisionResult.Stream,
            (plainData, streamProvisionResult) => (PlainData: plainData, StreamProvisionResult: streamProvisionResult));

        verificationVerdict = result.StreamProvisionResult.VerificationTask.Result;
        return result.PlainData;
    }

    public static ReadOnlyMemory<byte> DecryptAndVerify(
        this IVerificationCapablePgpDecrypter decrypter,
        string armoredSignedMessage,
        out VerificationVerdict verificationVerdict,
        out PgpSessionKey sessionKey)
    {
        var result = Decrypt(
            armoredSignedMessage,
            decrypter.GetDecryptingAndVerifyingStreamWithSessionKey,
            streamProvisionResult => streamProvisionResult.Stream,
            (plainData, streamProvisionResult) => (PlainData: plainData, StreamProvisionResult: streamProvisionResult));

        verificationVerdict = result.StreamProvisionResult.VerificationTask.Result;
        sessionKey = result.StreamProvisionResult.SessionKeyTask.Result;
        return result.PlainData;
    }

    public static ReadOnlyMemory<byte> DecryptAndVerify(
        this IVerificationCapablePgpDecrypter decrypter,
        string armoredMessage,
        string armoredSignature,
        out VerificationVerdict verificationVerdict)
    {
        var result = DecryptAndVerify(
            armoredMessage,
            armoredSignature,
            decrypter.GetDecryptingAndVerifyingStream,
            streamProvisionResult => streamProvisionResult.Stream,
            (plainData, streamProvisionResult) => (PlainData: plainData, StreamProvisionResult: streamProvisionResult));

        verificationVerdict = result.StreamProvisionResult.VerificationTask.Result;
        return result.PlainData;
    }

    public static ReadOnlyMemory<byte> DecryptAndVerify(
        this IVerificationCapablePgpDecrypter decrypter,
        string armoredMessage,
        string armoredSignature,
        out VerificationVerdict verificationVerdict,
        out PgpSessionKey sessionKey)
    {
        var result = DecryptAndVerify(
            armoredMessage,
            armoredSignature,
            decrypter.GetDecryptingAndVerifyingStreamWithSessionKey,
            streamProvisionResult => streamProvisionResult.Stream,
            (plainData, streamProvisionResult) => (PlainData: plainData, StreamProvisionResult: streamProvisionResult));

        verificationVerdict = result.StreamProvisionResult.VerificationTask.Result;
        sessionKey = result.StreamProvisionResult.SessionKeyTask.Result;
        return result.PlainData;
    }

    public static ReadOnlyMemory<byte> Decrypt(this IPgpDecrypter decrypter, string armoredMessage)
    {
        return Decrypt(armoredMessage, decrypter.GetDecryptingStream, x => x, (plainData, _) => plainData);
    }

    public static ReadOnlyMemory<byte> Decrypt(this IPgpDecrypter decrypter, string armoredMessage, out PgpSessionKey sessionKey)
    {
        var result = Decrypt(
            armoredMessage,
            decrypter.GetDecryptingStreamWithSessionKey,
            streamProvisionResult => streamProvisionResult.Stream,
            (plainData, streamProvisionResult) => (PlainData: plainData, streamProvisionResult.SessionKey));

        sessionKey = result.SessionKey.Result;
        return result.PlainData;
    }

    public static string DecryptAndVerifyText(
        this IVerificationCapablePgpDecrypter decrypter,
        string armoredSignedMessage,
        out VerificationVerdict verificationVerdict)
    {
        var result = DecryptText(
            armoredSignedMessage,
            decrypter.GetDecryptingAndVerifyingStream,
            streamProvisionResult => streamProvisionResult.Stream,
            (plainData, streamProvisionResult) => (PlainData: plainData, streamProvisionResult.VerificationTask));

        verificationVerdict = result.VerificationTask.Result;
        return result.PlainData;
    }

    public static string DecryptAndVerifyText(
        this IVerificationCapablePgpDecrypter decrypter,
        string armoredSignedMessage,
        out VerificationVerdict verificationVerdict,
        out PgpSessionKey sessionKey)
    {
        var result = DecryptText(
            armoredSignedMessage,
            decrypter.GetDecryptingAndVerifyingStreamWithSessionKey,
            x => x.Stream,
            (plainData, result) => (PlainText: plainData, StreamProvisionResult: result));

        verificationVerdict = result.StreamProvisionResult.VerificationTask.Result;
        sessionKey = result.StreamProvisionResult.SessionKeyTask.Result;
        return result.PlainText;
    }

    public static string DecryptText(this IPgpDecrypter decrypter, string armoredMessage)
    {
        return DecryptText(armoredMessage, decrypter.GetDecryptingStream, x => x, (plainData, _) => plainData);
    }

    public static string DecryptText(this IPgpDecrypter decrypter, string armoredMessage, out PgpSessionKey sessionKey)
    {
        var result = DecryptText(
            armoredMessage,
            decrypter.GetDecryptingStreamWithSessionKey,
            streamProvisionResult => streamProvisionResult.Stream,
            (plainData, streamProvisionResult) => (PlainText: plainData, streamProvisionResult.SessionKey));

        sessionKey = result.SessionKey.Result;
        return result.PlainText;
    }

    private static TResult DecryptAndVerify<TStreamProvisionResult, TResult>(
        string armoredMessage,
        string armoredSignature,
        Func<PgpMessageSource, PgpSignatureSource, TStreamProvisionResult> getStreamFunction,
        Func<TStreamProvisionResult, Stream> streamGetter,
        Func<ReadOnlyMemory<byte>, TStreamProvisionResult, TResult> createResultFunction)
    {
        PgpSignatureSource? signature = null;

        try
        {
            return Decrypt(
                armoredMessage,
                message =>
                {
                    signature = new PgpSignatureSource(new AsciiStream(armoredSignature), PgpArmoring.Ascii);
                    return getStreamFunction.Invoke(message, signature);
                },
                streamGetter,
                createResultFunction);
        }
        finally
        {
            signature?.Dispose();
        }
    }

    private static TResult Decrypt<TStreamProvisionResult, TResult>(
        string armoredMessage,
        Func<PgpMessageSource, TStreamProvisionResult> getStreamFunction,
        Func<TStreamProvisionResult, Stream> streamGetter,
        Func<ReadOnlyMemory<byte>, TStreamProvisionResult, TResult> createResultFunction)
    {
        var buffer = new byte[armoredMessage.Length];

        using var message = new PgpMessageSource(new AsciiStream(armoredMessage), PgpArmoring.Ascii);
        using var outputStream = new MemoryStream(buffer, true);
        var getStreamResult = getStreamFunction.Invoke(message);
        using var decryptingStream = streamGetter.Invoke(getStreamResult);

        var byteCount = decryptingStream.Read(buffer, 0, buffer.Length);

        return createResultFunction.Invoke(buffer.AsMemory(0, byteCount), getStreamResult);
    }

    private static TResult DecryptText<TStreamResult, TResult>(
        string armoredMessage,
        Func<PgpMessageSource, TStreamResult> getStreamFunction,
        Func<TStreamResult, Stream> streamGetter,
        Func<string, TStreamResult, TResult> createResultFunction)
    {
        using var message = new PgpMessageSource(new AsciiStream(armoredMessage), PgpArmoring.Ascii);
        var getStreamResult = getStreamFunction.Invoke(message);
        using var decryptingStream = streamGetter.Invoke(getStreamResult);
        using var streamReader = new StreamReader(decryptingStream, Encoding.UTF8);

        return createResultFunction.Invoke(streamReader.ReadToEnd(), getStreamResult);
    }
}
