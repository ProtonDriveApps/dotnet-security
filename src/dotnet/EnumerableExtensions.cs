using System.Collections;

namespace Proton.Security;

internal static class EnumerableExtensions
{
    public static IReadOnlyCollection<TResult> Select<T, TResult>(this IReadOnlyCollection<T> collection, Func<T, TResult> selector)
    {
        return Enumerable.Select(collection, selector).AsReadOnlyCollection(collection.Count);
    }

    public static IReadOnlyCollection<TResult> Select<T, TResult>(this ICollection<T> collection, Func<T, TResult> selector)
    {
        return Enumerable.Select(collection, selector).AsReadOnlyCollection(collection.Count);
    }

    public static IReadOnlyCollection<T> AsReadOnlyCollection<T>(this IEnumerable<T> enumerable, int count)
    {
        return new EnumerableToCollectionWrapper<T>(enumerable, count);
    }

    private sealed class EnumerableToCollectionWrapper<T> : IReadOnlyCollection<T>
    {
        private readonly IEnumerable<T> _enumerable;

        public EnumerableToCollectionWrapper(IEnumerable<T> enumerable, int count)
        {
            _enumerable = enumerable;
            Count = count;
        }

        public int Count { get; }

        public IEnumerator<T> GetEnumerator() => _enumerable.GetEnumerator();
        IEnumerator IEnumerable.GetEnumerator() => _enumerable.GetEnumerator();
    }
}
