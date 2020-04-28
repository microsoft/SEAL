// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

using Microsoft.Research.SEAL;
using System;

namespace SEALNetExamples
{
    partial class Examples
    {
        static void Main(string[] args)
        {
            Console.WriteLine("Microsoft SEAL version: " + SEALVersion.Version);
            while (true)
            {
                Console.WriteLine("+---------------------------------------------------------+");
                Console.WriteLine("| The following examples should be executed while reading |");
                Console.WriteLine("| comments in associated files in dotnet/examples/.       |");
                Console.WriteLine("+---------------------------------------------------------+");
                Console.WriteLine("| Examples                   | Source Files               |");
                Console.WriteLine("+----------------------------+----------------------------+");
                Console.WriteLine("| 1. BFV Basics              | 1_BFV_Basics.cs            |");
                Console.WriteLine("| 2. Encoders                | 2_Encoders.cs              |");
                Console.WriteLine("| 3. Levels                  | 3_Levels.cs                |");
                Console.WriteLine("| 4. CKKS Basics             | 4_CKKS_Basics.cs           |");
                Console.WriteLine("| 5. Rotation                | 5_Rotation.cs              |");
                Console.WriteLine("| 6. Serialization           | 6_Serialization.cs         |");
                Console.WriteLine("| 7. Performance Test        | 7_Performance.cs           |");
                Console.WriteLine("+----------------------------+----------------------------+");

                /*
                Print how much memory we have allocated from the current memory pool.
                By default the memory pool will be a static global pool and the
                MemoryManager class can be used to change it. Most users should have
                little or no reason to touch the memory allocation system.
                */
                ulong megabytes = MemoryManager.GetPool().AllocByteCount >> 20;
                Console.WriteLine("[{0,7} MB] Total allocation from the memory pool", megabytes);

                ConsoleKeyInfo key;
                do
                {
                    Console.WriteLine();
                    Console.Write("> Run example (1 ~ 7) or exit (0): ");
                    key = Console.ReadKey();
                    Console.WriteLine();
                } while (key.KeyChar < '0' || key.KeyChar > '7');
                switch (key.Key)
                {
                    case ConsoleKey.D1:
                        ExampleBFVBasics();
                        break;

                    case ConsoleKey.D2:
                        ExampleEncoders();
                        break;

                    case ConsoleKey.D3:
                        ExampleLevels();
                        break;

                    case ConsoleKey.D4:
                        ExampleCKKSBasics();
                        break;

                    case ConsoleKey.D5:
                        ExampleRotation();
                        break;

                    case ConsoleKey.D6:
                        ExampleSerialization();
                        break;

                    case ConsoleKey.D7:
                        ExamplePerformanceTest();
                        break;

                    case ConsoleKey.D0:
                        return;

                    default:
                        Console.WriteLine("  [Beep~~] Invalid option: type 0 ~ 7");
                        break;
                }

                /*
                We may want to force a garbage collection after each example to accurately show memory pool use.
                */
                GC.Collect();
            }
        }
    }
}
