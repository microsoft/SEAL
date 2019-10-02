using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.CompilerServices;
using System.Text;

namespace SEALNetTest
{
    /// <summary>
    /// Test utilities
    /// </summary>
    public static class Utilities
    {
        internal static int WorkaroundInstanceCount { get; private set; } = 0;

        public static void AssertThrow<T>(Func<object> action, [CallerFilePath] string caller = "", [CallerLineNumber] int line = 0) where T : Exception
        {
            DoAssertThrow<T>(() => { var result = action(); }, caller, line);
        }

        public static void AssertThrow<T>(Action action, [CallerFilePath] string caller = "", [CallerLineNumber] int line = 0) where T : Exception
        {
            DoAssertThrow<T>(action, caller, line);
        }

        private static void DoAssertThrow<T>(Action action, string caller, int line) where T : Exception
        {
            string strT = typeof(T).ToString();

            try
            {
                action();
            }
            catch (Exception ex)
            {
                T ourType = ex as T;

                if (null != ourType)
                {
                    // Expected exception throws
                    return;
                }

                // Workaround: Check if exception is FileNotFoundException
                FileNotFoundException waex = ex as FileNotFoundException;
                if (null != waex)
                {
                    string strWaex = waex.GetType().ToString();
                    Trace.WriteLine($"WARNING: {caller}:{line}: Expected exception of type '{strT}', got type '{strWaex}' instead.");
                    WorkaroundInstanceCount++;
                    return;
                }

                // Any other exception should fail.
                string strEx = ex.GetType().ToString();
                Assert.Fail($"{caller}:{line}: Expected exception of type '{strT}', got type '{strEx}' instead.");
            }

            Assert.Fail($"{caller}:{line}: Expected exception of type '{strT}', no exception thrown.");
        }
    }
}
