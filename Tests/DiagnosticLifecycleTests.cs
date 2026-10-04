using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Reflection;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace DiagnosticLifecycleRegression
{
    // Load the actual architecture-matched application. Only diagnostic work
    // delegates are synthetic; the real MainForm and WinForms message loop run.
    internal static class Program
    {
        private const BindingFlags HiddenInstance = BindingFlags.Instance | BindingFlags.NonPublic;
        private static Assembly application;
        private static Type mainType;
        private static Form host;
        private static int failures;
        private static int cases;
        private static int uiThread;

        [STAThread]
        private static int Main(string[] args)
        {
            if (args.Length == 1 && args[0] == "--child-success")
                return 0;
            if (args.Length == 2 && args[0] == "--child-marker")
            {
                File.WriteAllText(args[1], "synthetic child started");
                Thread.Sleep(30000);
                return 0;
            }
            if (args.Length != 1)
            {
                Console.Error.WriteLine("Usage: DiagnosticLifecycle.Tests.exe <matching-architecture application.exe>");
                return 2;
            }

            try
            {
                application = Assembly.LoadFrom(Path.GetFullPath(args[0]));
                mainType = application.GetType("DomainMembershipCheckRepair.MainForm", true);
                uiThread = Thread.CurrentThread.ManagedThreadId;
                Control.CheckForIllegalCrossThreadCalls = true;
                Application.SetUnhandledExceptionMode(UnhandledExceptionMode.CatchException);
                Application.ThreadException += delegate(object sender, ThreadExceptionEventArgs e)
                {
                    failures++;
                    Console.Error.WriteLine("FAIL: unhandled UI exception: " + e.Exception);
                };
                Application.EnableVisualStyles();
                Application.SetCompatibleTextRenderingDefault(false);
                using (System.Threading.Timer watchdog = new System.Threading.Timer(delegate
                {
                    Console.Error.WriteLine("FAIL: lifecycle tests exceeded the global timeout (possible unexpected modal dialog).");
                    Environment.Exit(1);
                }, null, 120000, Timeout.Infinite))
                using (host = new Form { Text = "Diagnostic lifecycle test host", Size = new Size(240, 100), ShowInTaskbar = false })
                {
                    host.Shown += async delegate
                    {
                        try { await RunAll(); }
                        catch (Exception ex) { failures++; Console.Error.WriteLine("FAIL: test harness: " + ex); }
                        finally { host.Close(); }
                    };
                    Application.Run(host);
                }
            }
            catch (Exception ex)
            {
                failures++;
                Console.Error.WriteLine("FAIL: test startup: " + ex);
            }
            Console.WriteLine("Diagnostic lifecycle cases: " + cases + "; failures: " + failures + ".");
            Console.WriteLine("Actual MainForm/STA message pump and benign test-child processes were used; no djoin, UAC request, restart or AD mutation.");
            return failures == 0 ? 0 : 1;
        }

        private static async Task RunAll()
        {
            await Case("completion and progress stay on the UI thread", NormalCompletion);
            await Case("cancel suppresses completion and disposes only after worker exit", CancelActive);
            await Case("late progress cannot overwrite a completed operation", LateProgress);
            await Case("old progress cannot overwrite the next operation", OldProgressDuringNext);
            await Case("cancel during SetBusy message pumping prevents work", CancelBeforeWork);
            await Case("close during SetBusy message pumping prevents work", CloseBeforeWork);
            await Case("close suppresses late successful results", CloseActive);
            await Case("direct Dispose cancels active work", DisposeActive);
            await Case("fault after close cannot display a late error dialog", FaultAfterClose);
            await Case("handle recreation preserves active diagnostics", RecreateHandle);
            await Case("vetoed close allows a subsequent diagnostic", VetoClose);
            await Case("throwing cancellation callback does not block close", ThrowingCancelCallback);
            await Case("pre-cancelled raw command never starts a process", PreCancelledRaw);
            await Case("pre-cancelled argv command never enumerates arguments", PreCancelledArguments);
            await Case("already-running benign helper observes cancellation", CancelRunningHelper);
            await Case("normal benign helper still succeeds", SuccessfulHelper);
        }

        private static async Task Case(string name, Func<Task> test)
        {
            cases++;
            int before = failures;
            try
            {
                await test();
                await Drain(host);
                if (failures == before) Console.WriteLine("PASS: " + name);
                else Console.Error.WriteLine("FAIL: " + name + " raised an asynchronous UI exception.");
            }
            catch (Exception ex)
            {
                failures++;
                Console.Error.WriteLine("FAIL: " + name + ": " + ex);
            }
        }

        private static void Check(bool value, string message)
        {
            if (!value) throw new InvalidOperationException(message);
        }

        private static async Task Until(Func<bool> ready, string description)
        {
            Stopwatch clock = Stopwatch.StartNew();
            while (!ready())
            {
                if (clock.ElapsedMilliseconds > 10000) throw new TimeoutException(description);
                await Task.Delay(10);
            }
        }

        private static Task Drain(Control control)
        {
            TaskCompletionSource<bool> done = new TaskCompletionSource<bool>();
            control.BeginInvoke(new MethodInvoker(delegate { done.SetResult(true); }));
            return done.Task;
        }

        private sealed class Fixture : IDisposable
        {
            internal readonly Form Form;
            internal Fixture()
            {
                Form = (Form)Activator.CreateInstance(mainType,
                    HiddenInstance | BindingFlags.Public, null,
                    new object[] { false, new string[0], true }, null);
                Form.ShowInTaskbar = false;
                Form.Show(host);
                Check(Form.IsHandleCreated, "MainForm handle was not created.");
            }
            internal T Field<T>(string name)
            {
                FieldInfo field = mainType.GetField(name, HiddenInstance);
                if (field == null) throw new MissingFieldException(name);
                return (T)field.GetValue(Form);
            }
            internal CancellationTokenSource Source { get { return Field<CancellationTokenSource>("diagnosticsCancellation"); } }
            internal string Progress { get { return Field<Label>("diagnosticsProgressLabel").Text; } }
            internal void Start(string name, Func<CancellationToken, Action<string>, int> work, Action<int> completed)
            {
                mainType.GetMethod("RunBackgroundDiagnostic", HiddenInstance).MakeGenericMethod(typeof(int))
                    .Invoke(Form, new object[] { name, work, completed });
            }
            internal void Cancel()
            {
                mainType.GetMethod("CancelDiagnosticOperation", HiddenInstance).Invoke(Form, null);
            }
            internal async Task Idle()
            {
                await Until(delegate { return Source == null; }, "diagnostic cleanup did not finish");
                await Drain(host);
            }
            public void Dispose() { Form.Dispose(); }
        }

        private sealed class Gate : IDisposable
        {
            internal readonly ManualResetEventSlim Entered = new ManualResetEventSlim(false);
            internal readonly ManualResetEventSlim Release = new ManualResetEventSlim(false);
            internal readonly ManualResetEventSlim Exited = new ManualResetEventSlim(false);
            internal Action<string> Report;
            internal CancellationToken Token;
            internal bool Fail;
            internal bool ThrowOnCancel;
            internal int WorkerThread;
            internal int Work(CancellationToken token, Action<string> report)
            {
                CancellationTokenRegistration registration = default(CancellationTokenRegistration);
                try
                {
                    Token = token;
                    Report = report;
                    WorkerThread = Thread.CurrentThread.ManagedThreadId;
                    if (ThrowOnCancel)
                        registration = token.Register(delegate { throw new InvalidOperationException("synthetic cancellation callback failure"); });
                    Entered.Set();
                    // Intentionally ignore cancellation until released: late
                    // success/failure must still be suppressed by the real UI.
                    if (!Release.Wait(15000)) throw new TimeoutException("synthetic worker not released");
                    if (Fail) throw new InvalidOperationException("synthetic worker failure");
                    return 42;
                }
                finally { registration.Dispose(); Exited.Set(); }
            }
            public void Dispose()
            {
                Release.Set();
                if (Entered.IsSet) Exited.Wait(2000);
                // Do not dispose event handles while an unexpectedly late worker
                // might still enter. They are confined to this short-lived test process.
            }
        }

        private static async Task NormalCompletion()
        {
            using (Fixture f = new Fixture())
            using (Gate g = new Gate())
            {
                int calls = 0;
                f.Start("normal", g.Work, delegate(int result)
                {
                    Check(Thread.CurrentThread.ManagedThreadId == uiThread, "Completion left UI thread.");
                    Check(result == 42, "Wrong result.");
                    calls++;
                });
                await Until(delegate { return g.Entered.IsSet; }, "worker did not start");
                Check(g.WorkerThread != uiThread, "Work ran on UI thread.");
                await Task.Run(delegate { g.Report("normal progress"); });
                await Drain(f.Form);
                Check(f.Progress == "normal progress", "Progress did not reach UI.");
                g.Release.Set();
                await f.Idle();
                Check(calls == 1 && f.Progress == "normal: completed.", "Normal completion was not delivered exactly once.");
                Check(f.Field<Button>("checkButton").Enabled, "Busy state remained set.");
            }
        }

        private static async Task CancelActive()
        {
            using (Fixture f = new Fixture())
            using (Gate g = new Gate())
            {
                int calls = 0;
                f.Start("cancel", g.Work, delegate { calls++; });
                await Until(delegate { return g.Entered.IsSet; }, "worker did not start");
                CancellationTokenSource source = f.Source;
                f.Cancel();
                Check(g.Token.IsCancellationRequested, "Worker was not notified.");
                Check(source.Token.IsCancellationRequested, "Source disposed before worker returned.");
                g.Release.Set();
                await f.Idle();
                await Until(delegate
                {
                    try { CancellationToken ignored = source.Token; return false; }
                    catch (ObjectDisposedException) { return true; }
                }, "source was not disposed after worker completion");
                Check(calls == 0 && f.Progress == "cancel: cancelled.", "Cancelled result was delivered.");
            }
        }

        private static async Task LateProgress()
        {
            using (Fixture f = new Fixture())
            using (Gate g = new Gate())
            {
                f.Start("first", g.Work, null);
                await Until(delegate { return g.Entered.IsSet; }, "worker did not start");
                g.Release.Set();
                await f.Idle();
                await Task.Run(delegate { g.Report("STALE"); });
                await Drain(f.Form);
                Check(f.Progress == "first: completed.", "Late progress overwrote final state.");
            }
        }

        private static async Task OldProgressDuringNext()
        {
            using (Fixture f = new Fixture())
            using (Gate old = new Gate())
            using (Gate next = new Gate())
            {
                f.Start("old", old.Work, null);
                await Until(delegate { return old.Entered.IsSet; }, "old worker did not start");
                old.Release.Set();
                await f.Idle();
                f.Start("next", next.Work, null);
                await Until(delegate { return next.Entered.IsSet; }, "next worker did not start");
                await Task.Run(delegate { next.Report("CURRENT"); });
                await Drain(f.Form);
                await Task.Run(delegate { old.Report("STALE"); });
                await Drain(f.Form);
                Check(f.Progress == "CURRENT", "Previous operation overwrote current status.");
                next.Release.Set();
                await f.Idle();
            }
        }

        private static async Task CancelBeforeWork()
        {
            using (Fixture f = new Fixture())
            {
                int calls = 0;
                f.Form.BeginInvoke(new MethodInvoker(f.Cancel));
                f.Start("early cancel", delegate { Interlocked.Increment(ref calls); return 42; }, null);
                await f.Idle();
                Check(calls == 0, "Cancelled operation started work after message pumping.");
            }
        }

        private static async Task CloseBeforeWork()
        {
            using (Fixture f = new Fixture())
            {
                int calls = 0;
                f.Form.BeginInvoke(new MethodInvoker(f.Form.Close));
                f.Start("early close", delegate { Interlocked.Increment(ref calls); return 42; }, null);
                await f.Idle();
                Check(f.Form.IsDisposed && calls == 0, "Closed operation started work.");
            }
        }

        private static async Task CloseActive() { await CloseOrDispose(false, false, false); }
        private static async Task DisposeActive() { await CloseOrDispose(true, false, false); }
        private static async Task FaultAfterClose() { await CloseOrDispose(false, true, false); }
        private static async Task ThrowingCancelCallback() { await CloseOrDispose(false, false, true); }

        private static async Task CloseOrDispose(bool dispose, bool fault, bool badCallback)
        {
            using (Fixture f = new Fixture())
            using (Gate g = new Gate { Fail = fault, ThrowOnCancel = badCallback })
            {
                int calls = 0;
                f.Start("closing", g.Work, delegate { calls++; });
                await Until(delegate { return g.Entered.IsSet; }, "worker did not start");
                if (dispose) f.Form.Dispose(); else f.Form.Close();
                Check(f.Form.IsDisposed, "Window did not close.");
                Check(g.Token.IsCancellationRequested, "Closing/disposing did not cancel work.");
                g.Release.Set();
                await f.Idle();
                await Task.Run(delegate { g.Report("late after close"); });
                Check(calls == 0, "Closed form received completion.");
            }
        }

        private static async Task RecreateHandle()
        {
            using (Fixture f = new Fixture())
            using (Gate g = new Gate())
            {
                int calls = 0;
                f.Start("recreate", g.Work, delegate { calls++; });
                await Until(delegate { return g.Entered.IsSet; }, "worker did not start");
                typeof(Control).GetMethod("RecreateHandle", HiddenInstance).Invoke(f.Form, null);
                Check(f.Form.IsHandleCreated && !g.Token.IsCancellationRequested, "Handle recreation was treated as permanent close.");
                g.Release.Set();
                await f.Idle();
                Check(calls == 1, "Recreated form lost completion.");
            }
        }

        private static async Task VetoClose()
        {
            using (Fixture f = new Fixture())
            using (Gate g = new Gate())
            {
                FormClosingEventHandler veto = delegate(object sender, FormClosingEventArgs e) { e.Cancel = true; };
                f.Form.FormClosing += veto;
                f.Start("veto", g.Work, null);
                await Until(delegate { return g.Entered.IsSet; }, "worker did not start");
                f.Form.Close();
                Check(!f.Form.IsDisposed, "Vetoed window was disposed.");
                g.Release.Set();
                await f.Idle();
                f.Form.FormClosing -= veto;
                int calls = 0;
                f.Start("after veto", delegate { return 42; }, delegate { calls++; });
                await f.Idle();
                Check(calls == 1, "Vetoed close permanently blocked diagnostics.");
            }
        }

        private static object RunHelper(string method, object arguments, CancellationToken token)
        {
            Type type = application.GetType("DomainMembershipCheckRepair.ProcessRunner", true);
            Type argumentType = method == "Run" ? typeof(string) : typeof(IEnumerable<string>);
            MethodInfo run = type.GetMethod(method, BindingFlags.Static | BindingFlags.NonPublic,
                null, new Type[] { typeof(string), argumentType, typeof(int), typeof(CancellationToken) }, null);
            return run.Invoke(null, new object[] { Assembly.GetExecutingAssembly().Location, arguments, 15000, token });
        }
        private static T Result<T>(object result, string name)
        {
            return (T)result.GetType().GetField(name, HiddenInstance).GetValue(result);
        }
        private static void CheckNotStarted(object result)
        {
            Check(!Result<bool>(result, "Started") && Result<bool>(result, "Cancelled") &&
                !Result<bool>(result, "TimedOut") && Result<int>(result, "ExitCode") == -1,
                "Pre-cancelled process returned incorrect state or was started.");
        }
        private static async Task PreCancelledRaw()
        {
            string marker = Path.Combine(Path.GetTempPath(), "dmcr-cancel-" + Guid.NewGuid().ToString("N") + ".txt");
            try
            {
                using (CancellationTokenSource source = new CancellationTokenSource())
                {
                    source.Cancel();
                    CheckNotStarted(RunHelper("Run", "--child-marker \"" + marker + "\"", source.Token));
                    await Task.Delay(50);
                    Check(!File.Exists(marker), "Pre-cancelled helper wrote its marker.");
                }
            }
            finally { if (File.Exists(marker)) File.Delete(marker); }
        }
        private static IEnumerable<string> NeverEnumerate()
        {
            throw new InvalidOperationException("Pre-cancelled arguments were enumerated.");
#pragma warning disable CS0162
            yield break;
#pragma warning restore CS0162
        }
        private static Task PreCancelledArguments()
        {
            using (CancellationTokenSource source = new CancellationTokenSource())
            {
                source.Cancel();
                CheckNotStarted(RunHelper("RunArguments", NeverEnumerate(), source.Token));
            }
            return Task.CompletedTask;
        }
        private static async Task CancelRunningHelper()
        {
            string marker = Path.Combine(Path.GetTempPath(), "dmcr-running-" + Guid.NewGuid().ToString("N") + ".txt");
            try
            {
                using (CancellationTokenSource source = new CancellationTokenSource())
                {
                    Task<object> running = Task.Run(delegate
                    {
                        return RunHelper("RunArguments", new string[] { "--child-marker", marker }, source.Token);
                    });
                    try
                    {
                        await Until(delegate { return File.Exists(marker) || running.IsCompleted; }, "helper failed to start");
                        Check(File.Exists(marker), "Helper ended before marker creation.");
                    }
                    finally { source.Cancel(); }
                    object result = await running;
                    Check(Result<bool>(result, "Started") && Result<bool>(result, "Cancelled") &&
                        !Result<bool>(result, "TimedOut"), "Running helper did not report cancellation.");
                }
            }
            finally { if (File.Exists(marker)) File.Delete(marker); }
        }
        private static async Task SuccessfulHelper()
        {
            object result = await Task.Run(delegate
            {
                return RunHelper("RunArguments", new string[] { "--child-success" }, CancellationToken.None);
            });
            Check(Result<bool>(result, "Started") && !Result<bool>(result, "Cancelled") &&
                !Result<bool>(result, "TimedOut") && Result<int>(result, "ExitCode") == 0,
                "Normal helper execution regressed.");
        }
    }
}
