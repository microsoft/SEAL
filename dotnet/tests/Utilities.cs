// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.CompilerServices;

namespace SEALNetTest
{
    /// <summary>
    /// Test utilities
    /// </summary>
    public static class Utilities
    {
        internal static int WorkaroundInstanceCount { get; private set; } = 0;

        /// <summary>
        /// Assert that an exception of the given type is thrown.
        ///
        /// This is a workaround for a unit testing issue in VS 2019.
        /// When running unit tests a couple of them fail because of a FileNotFoundException being thrown instead
        /// of the expected exception. The FileNotFoundException is thrown in the boundary between a .Net call
        /// and a native method, so there is not really much we can do to fix it. As a workaround this method
        /// works as Assert.ThrowsException, but allows FileNotFoundException as well, and outputs a warning when
        /// it is found.
        /// </summary>
        /// <typeparam name="T">Expected exception type</typeparam>
        /// <param name="action">Function to run that should throw an exception</param>
        /// <param name="caller">Path to the source file that called this method</param>
        /// <param name="line">Line in the source file that called this method</param>
        public static void AssertThrows<T>(Func<object> action, [CallerFilePath] string caller = "", [CallerLineNumber] int line = 0) where T : Exception
        {
            DoAssertThrow<T>(() => { var result = action(); }, caller, line);
        }

        /// <summary>
        /// Assert that an exception of the given type is thrown.
        ///
        /// This is a workaround for a unit testing issue in VS 2019.
        /// When running unit tests a couple of them fail because of a FileNotFoundException being thrown instead
        /// of the expected exception. The FileNotFoundException is thrown in the boundary between a .Net call
        /// and a native method, so there is not really much we can do to fix it. As a workaround this method
        /// works as Assert.ThrowsException, but allows FileNotFoundException as well, and outputs a warning when
        /// it is found.
        /// </summary>
        /// <typeparam name="T">Expected exception type</typeparam>
        /// <param name="action">Action to run that should throw an exception</param>
        /// <param name="caller">Path to the source file that called this method</param>
        /// <param name="line">Line in the source file that called this method</param>
        public static void AssertThrows<T>(Action action, [CallerFilePath] string caller = "", [CallerLineNumber] int line = 0) where T : Exception
        {
            DoAssertThrow<T>(action, caller, line);
        }

        private static void DoAssertThrow<T>(Action action, string caller, int line) where T : Exception
        {
            string expectedStr = typeof(T).ToString();

            try
            {
                action();
            }
            catch (Exception ex)
            {
                if (ex is T)
                {
                    // Expected exception has been thrown
                    return;
                }

                // Workaround: Check if exception is FileNotFoundException
                if (ex is FileNotFoundException workaroundExc)
                {
                    string workaroundStr = workaroundExc.GetType().ToString();
                    Trace.WriteLine($"WARNING: {caller}:{line}: Expected exception of type '{expectedStr}', got type '{workaroundStr}' instead.");
                    WorkaroundInstanceCount++;
                    return;
                }

                // Any other exception should fail.
                string actualStr = ex.GetType().ToString();
                Assert.Fail($"{caller}:{line}: Expected exception of type '{expectedStr}', got type '{actualStr}' instead.");
            }

            Assert.Fail($"{caller}:{line}: Expected exception of type '{expectedStr}', no exception thrown.");
        }
    }
}
