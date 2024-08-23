namespace Proton.Security.Cryptography;

internal static class ParallelTask
{
    /// <summary>
    /// Creates a task that will complete when both tasks created by the supplied factories have completed.
    /// </summary>
    /// <remarks>
    /// Differs from <see cref="Task.WhenAll(Task[])"/> in that it takes factories of tasks,
    /// which allows it to handle calls that may fail before returning a task, such as some of those containing parameter validation.
    /// It can be used to execute actions upon failure, for example to dispose the result of one task when the other fails.
    /// And finally, the returned task directly provides the results of both tasks even when their types differ.
    /// </remarks>
    /// <typeparam name="T1">Type of the result of task 1.</typeparam>
    /// <typeparam name="T2">Type of the result of task 2.</typeparam>
    /// <returns>A task that represents the completion of both tasks created by the supplied factories.</returns>
    public static async Task<(T1 Result1, T2 Result2)> WhenBoth<T1, T2>(
        Func<Task<T1>> task1Factory,
        Func<Task<T2>> task2Factory,
        Func<T1, Task>? task1FailureAction = default,
        Func<T2, Task>? task2FailureAction = default)
    {
        var task1 = task1Factory.Invoke();

        T1 result1;
        T2 result2;
        try
        {
            result2 = await task2Factory.Invoke().ConfigureAwait(false);
        }
        catch
        {
            result1 = await task1.ConfigureAwait(false);
            if (task1FailureAction is not null)
            {
                await task1FailureAction.Invoke(result1).ConfigureAwait(false);
            }

            throw;
        }

        try
        {
            result1 = await task1.ConfigureAwait(false);
        }
        catch
        {
            if (task2FailureAction is not null)
            {
                await task2FailureAction.Invoke(result2).ConfigureAwait(false);
            }

            throw;
        }

        return (result1, result2);
    }

    /// <summary>
    /// Creates a task that will complete when both tasks created by the supplied factories have completed.
    /// </summary>
    /// <remarks>
    /// Differs from <see cref="Task.WhenAll(Task[])"/> in that it takes factories of tasks,
    /// which allows it to handle calls that may fail before returning a task, such as some of those containing parameter validation.
    /// </remarks>
    /// <returns>A task that represents the completion of both tasks created by the supplied factories.</returns>
    public static async Task WhenBoth(Func<Task> task1Factory, Func<Task> task2Factory)
    {
        var task1 = task1Factory.Invoke();

        try
        {
            await task2Factory.Invoke().ConfigureAwait(false);
        }
        catch
        {
            await task1.ConfigureAwait(false);
            throw;
        }

        await task1.ConfigureAwait(false);
    }

    public static Task<(T1 Result1, T2 Result2)> WhenBothDisposable<T1, T2>(Func<Task<T1>> task1Factory, Func<Task<T2>> task2Factory)
        where T1 : IDisposable
        where T2 : IDisposable
    {
        return WhenBoth(task1Factory, task2Factory, r1 => DisposeResultAsync(r1), r2 => DisposeResultAsync(r2));

        static Task DisposeResultAsync(IDisposable result)
        {
            result.Dispose();
            return Task.CompletedTask;
        }
    }
}
