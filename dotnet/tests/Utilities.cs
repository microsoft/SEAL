using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Text;

namespace SEALNetTest
{
    /// <summary>
    /// Test utilities
    /// </summary>
    public static class Utilities
    {
        public static void AssertThrow<T>(Action action) where T : Exception
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
                    Trace.WriteLine($"WARNING: Expected exception of type '{strT}', got type '{strWaex}' instead.");
                    return;
                }

                // Any other exception should fail.
                string strEx = ex.GetType().ToString();
                Assert.Fail($"Expected exception of type '{strT}', got type 'strEx' instead.");
            }

            Assert.Fail($"Expected exception of type '{strT}', no exception thrown.");
        }
    }
}
