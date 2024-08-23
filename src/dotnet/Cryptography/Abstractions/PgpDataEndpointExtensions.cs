namespace Proton.Security.Cryptography.Abstractions;

internal static class PgpDataEndpointExtensions
{
    public static async Task<ReadOnlyMemory<byte>> GetBytesAsync(this DataEndpointBase dataEndPoint, CancellationToken cancellationToken)
    {
        Memory<byte> result;
        if (dataEndPoint.Stream is MemoryStream endPointMemoryStream)
        {
            result = endPointMemoryStream.TryGetBuffer(out var messageBytes)
                ? messageBytes
                : endPointMemoryStream.ToArray();
        }
        else if (dataEndPoint.Stream.CanSeek)
        {
            result = new byte[dataEndPoint.Stream.Length - dataEndPoint.Stream.Position];
            await dataEndPoint.Stream.ReadAsync(result, cancellationToken).ConfigureAwait(false);
        }
        else
        {
            // ReSharper disable once UseAwaitUsing (justification: memory stream does not need async disposal)
            using var memoryStream = new MemoryStream();

            await dataEndPoint.Stream.CopyToAsync(memoryStream, cancellationToken).ConfigureAwait(false);
            result = memoryStream.ToArray();
        }

        return result;
    }
}
