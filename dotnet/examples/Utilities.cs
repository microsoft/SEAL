// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

using Microsoft.Research.SEAL;
using System;
using System.Collections.Generic;
using System.Linq;

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

        /// <summary>
        /// Helper function: Print the first and last printSize elements of a 2 row matrix
        /// </summary>
        public static void PrintMatrix(IEnumerable<ulong> matrixPar, int rowSize, int printSize = 5)
        {
            ulong[] matrix = matrixPar.ToArray();
            Console.WriteLine();

            /*
            We're not going to print every column of the matrix (may be big). Instead
            print printSize slots from beginning and end of the matrix.
            */
            Console.Write("    [");
            for (int i = 0; i < printSize; i++)
            {
                Console.Write("{0,3}, ", matrix[i]);
            }
            Console.Write(" ...");
            for (int i = rowSize - printSize; i < rowSize; i++)
            {
                Console.Write(", {0,3}", matrix[i]);
            }
            Console.WriteLine("  ]");
            Console.Write("    [");
            for (int i = rowSize; i < rowSize + printSize; i++)
            {
                Console.Write("{0,3}, ", matrix[i]);
            }
            Console.Write(" ...");
            for (int i = 2 * rowSize - printSize; i < 2 * rowSize; i++)
            {
                Console.Write(", {0,3}", matrix[i]);
            }
            Console.WriteLine("  ]");
            Console.WriteLine();
        }

        /// <summary>
        /// Helper function: Convert a ulong to a hex string representation
        /// </summary>
        public static string ULongToString(ulong value)
        {
            byte[] bytes = BitConverter.GetBytes(value);
            return BitConverter.ToString(bytes).Replace("-", "");
        }

        /// <summary>
        /// Helper function: Prints a vector of floating-point values.
        /// </summary>
        public static void PrintVector<T>(IEnumerable<T> vec, int printSize = 4)
        {
            T[] veca = vec.ToArray();
            int slotCount = veca.Length;
            if (slotCount <= 2 * printSize)
            {
                Console.Write("    [");
                for (int i = 0; i < slotCount; i++)
                {
                    Console.Write(" {0:0.000}", veca[i]);
                    if (i != (slotCount - 1))
                        Console.Write(",");
                    else
                        Console.Write(" ]");
                }
                Console.WriteLine();
            }
            else
            {
                Console.Write("    [");
                for (int i = 0; i < printSize; i++)
                {
                    Console.Write(" {0:0.000},", veca[i]);
                }
                if (veca.Length > 2 * printSize)
                {
                    Console.Write(" ...");
                }
                for (int i = slotCount - printSize; i < slotCount; i++)
                {
                    Console.Write(", {0:0.000}", veca[i]);
                }
                Console.WriteLine(" ]");
            }

            Console.WriteLine();
        }
    }
}
