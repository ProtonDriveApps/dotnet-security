namespace Proton.Security;

public readonly struct Disposable<T> : IDisposable
{
    // TODO: make this a single action
    private readonly IEnumerable<Action> _disposalActions;

    public Disposable(T value, IEnumerable<Action> disposalActions)
    {
        Value = value;
        _disposalActions = disposalActions;
    }

    public Disposable(T value)
        : this(value, Enumerable.Empty<Action>())
    {
    }

    public Disposable(T value, params Action[] disposalActions)
        : this(value, (IEnumerable<Action>)disposalActions)
    {
    }

    public Disposable(T value, IEnumerable<IDisposable> disposables)
        : this(value, disposables.Select(disposable => new Action(disposable.Dispose)))
    {
    }

    public Disposable(T value, params IDisposable[] disposables)
        : this(value, (IEnumerable<IDisposable>)disposables)
    {
    }

    public T Value { get; }

    public void Dispose()
    {
        foreach (var action in _disposalActions)
        {
            action.Invoke();
        }
    }
}
