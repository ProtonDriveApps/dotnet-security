namespace Proton.Security;

public static class MemoryExtensions
{
    public static Stream AsReadOnlyStream(this ReadOnlyMemory<byte> memory)
    {
        return new ReadOnlyMemoryStream(memory);
    }

    public static Stream AsReadOnlyStream(this Memory<byte> memory)
    {
        return AsReadOnlyStream((ReadOnlyMemory<byte>)memory);
    }

    private sealed class ReadOnlyMemoryStream : WrappingStream
    {
        private readonly ReadOnlyMemoryContent _content;

        // We use an HTTP-related class because that's currently the only way to create an instance of the existing internal implementation.
        // There is an issue about making such a feature public: https://github.com/dotnet/runtime/issues/27156
        // And one about implementing it for .NET 7: https://github.com/dotnet/runtime/issues/58216
        public ReadOnlyMemoryStream(ReadOnlyMemory<byte> memory)
            : this(new ReadOnlyMemoryContent(memory))
        {
        }

        private ReadOnlyMemoryStream(ReadOnlyMemoryContent content)
            : base(content.ReadAsStream())
        {
            _content = content;
        }

        public override async ValueTask DisposeAsync()
        {
            await base.DisposeAsync().ConfigureAwait(false);

            _content.Dispose();
        }

        protected override void Dispose(bool disposing)
        {
            base.Dispose(disposing);

            if (disposing)
            {
                _content.Dispose();
            }
        }
    }
}
