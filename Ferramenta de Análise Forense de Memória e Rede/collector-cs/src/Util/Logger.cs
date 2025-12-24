using System;
using System.IO;

namespace ForensicCollector.Util
{
    public static class Logger
    {
        private static readonly object _lock = new object();
        private static string _logPath = Path.Combine(Path.GetTempPath(), "ForensicCollector-errors.log");
        // 0=off,1=warn,2=info
        private static int _level = 1;

        public static void Configure(string? path, string? level)
        {
            if (!string.IsNullOrWhiteSpace(path))
            {
                try
                {
                    var dir = Path.GetDirectoryName(path);
                    if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
                    _logPath = path;
                }
                catch { }
            }
            if (!string.IsNullOrWhiteSpace(level))
            {
                var lvl = level.Trim().ToLowerInvariant();
                _level = lvl switch
                {
                    "off" => 0,
                    "warn" => 1,
                    "info" => 2,
                    _ => _level
                };
            }
        }

        public static void Warn(string context, Exception ex)
        {
            if (_level < 1) return;
            try
            {
                var line = $"[{DateTime.UtcNow:O}] WARN [{context}] {ex.GetType().Name}: {ex.Message}";
                WriteLine(line);
            }
            catch { /* swallow logging errors */ }
        }

        public static void Info(string message)
        {
            if (_level < 2) return;
            try { WriteLine($"[{DateTime.UtcNow:O}] INFO {message}"); } catch { }
        }

        private static void WriteLine(string line)
        {
            lock (_lock)
            {
                File.AppendAllText(_logPath, line + Environment.NewLine);
            }
        }
    }
}
