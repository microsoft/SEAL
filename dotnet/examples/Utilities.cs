// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

using Microsoft.Research.SEAL;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;

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
                int bannerLength = titleLength + 2 * 10;
                string bannerTop = "+" + new string('-', bannerLength - 2) + "+";
                string bannerMiddle =
                    "|" + new string(' ', 9) + title + new string(' ', 9) + "|";

                Console.WriteLine();
                Console.WriteLine(bannerTop);
                Console.WriteLine(bannerMiddle);
                Console.WriteLine(bannerTop);
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
            SEALContext.ContextData contextData = context.KeyContextData;

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

            Console.WriteLine("/");
            Console.WriteLine("| Encryption parameters:");
            Console.WriteLine($"|   Scheme: {schemeName}");
            Console.WriteLine("|   PolyModulusDegree: {0}",
                contextData.Parms.PolyModulusDegree);

            /*
            Print the size of the true (product) coefficient modulus.
            */
            Console.Write("|   CoeffModulus size: {0} (",
                contextData.TotalCoeffModulusBitCount);
            List<Modulus> coeffModulus =
                (List<Modulus>)contextData.Parms.CoeffModulus;
            for (int i = 0; i < coeffModulus.Count - 1; i++)
            {
                Console.Write($"{coeffModulus[i].BitCount} + ");
            }
            Console.WriteLine($"{coeffModulus.Last().BitCount}) bits");

            /*
            For the BFV scheme print the PlainModulus parameter.
            */
            if (contextData.Parms.Scheme == SchemeType.BFV)
            {
                Console.WriteLine("|   PlainModulus: {0}",
                    contextData.Parms.PlainModulus.Value);
            }

            Console.WriteLine("\\");
        }

        /// <summary>
        /// Helper function: Print the first and last printSize elements
        /// of a 2 row matrix.
        /// </summary>
        public static void PrintMatrix(IEnumerable<ulong> matrixPar,
            int rowSize, int printSize = 5)
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
        public static void PrintVector<T>(
            IEnumerable<T> vec, int printSize = 4, int prec = 3)
        {
            string numFormat = string.Format("{{0:N{0}}}", prec);
            T[] veca = vec.ToArray();
            int slotCount = veca.Length;
            Console.WriteLine();
            if (slotCount <= 2 * printSize)
            {
                Console.Write("    [");
                for (int i = 0; i < slotCount; i++)
                {
                    Console.Write(" " + string.Format(numFormat, veca[i]));
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
                    Console.Write(" "+ string.Format(numFormat, veca[i]) + ", ");
                }
                if (veca.Length > 2 * printSize)
                {
                    Console.Write(" ...");
                }
                for (int i = slotCount - printSize; i < slotCount; i++)
                {
                    Console.Write(", " + string.Format(numFormat, veca[i]));
                }
                Console.WriteLine(" ]");
            }
            Console.WriteLine();
        }

        public static void PrintLine([CallerLineNumber] int lineNumber = 0)
        {
            Console.Write("Line {0,3} --> ", lineNumber);
        }
    }
}