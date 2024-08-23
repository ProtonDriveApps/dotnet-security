namespace Proton.Security.InteropServices;

internal static class GoInteropEnvironment
{
    private static readonly object SyncLock = new();
    private static bool _isInitialized;

    public static void EnsureInitialized()
    {
        if (_isInitialized)
        {
            return;
        }

        lock (SyncLock)
        {
            if (_isInitialized)
            {
                return;
            }

            Environment.SetEnvironmentVariable("GODEBUG", "cgocheck=0");
            _isInitialized = true;
        }
    }
}
