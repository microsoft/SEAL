using Microsoft.Research.SEAL;
using System;
using System.Collections.Generic;
using System.Text;

namespace SEALNetExamples
{
    public static class Utilities
    {
        /// <summary>
        /// Helper function: Prints the name of the example in a fancy banner.
        /// </summary>
        public static void PrintExampleBanner(string title)
        {
            if (!string.IsNullOrEmpty(title))
            {
                int titleLength = title.Length;
                int bannerLength = titleLength + 2 + 2 * 10;
                string bannerTop = new string('*', bannerLength);
                string bannerMiddle = new string('*', 10) + " " + title + " " + new string('*', 10);

                Console.WriteLine();
                Console.WriteLine(bannerTop);
                Console.WriteLine(bannerMiddle);
                Console.WriteLine(bannerTop);
                Console.WriteLine();
            }
        }

        /// <summary>
        /// Helper function: Prints the parameters in a SEALContext.
        /// </summary>
        public static void PrintParameters(SEALContext context)
        {
            // Verify parameters
            if (null == context)
            {
                throw new ArgumentNullException("context is not set");
            }

            SEALContext.ContextData contextData = context.FirstContextData;

            /*
            Which scheme are we using?
            */
            string schemeName = null;
            switch (contextData.Parms.Scheme)
            {
                case SchemeType.BFV:
                    schemeName = "BFV";
                    break;
                case SchemeType.CKKS:
                    schemeName = "CKKS";
                    break;
                default:
                    throw new ArgumentException("unsupported scheme");
            }

            Console.WriteLine($"/ Encryption parameters:");
            Console.WriteLine($"| Scheme: {schemeName}");
            Console.WriteLine($"| PolyModulusDegree: {contextData.Parms.PolyModulusDegree}");

            /*
            Print the size of the true (product) coefficient modulus.
            */
            Console.WriteLine($"| CoeffModulus size: {contextData.TotalCoeffModulusBitCount} bits");

            /*
            For the BFV scheme print the plain_modulus parameter.
            */
            if (contextData.Parms.Scheme == SchemeType.BFV)
            {
                Console.WriteLine($"| PlainModulus: {contextData.Parms.PlainModulus.Value}");
            }

            Console.WriteLine($"\\ NoiseStandardDeviation: {contextData.Parms.NoiseStandardDeviation}");
            Console.WriteLine();
        }

    }
}
