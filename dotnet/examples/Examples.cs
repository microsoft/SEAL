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
                Console.WriteLine("| 4. BGV Basics              | 4_BGV_Basics.cs            |");
                Console.WriteLine("| 5. CKKS Basics             | 5_CKKS_Basics.cs           |");
                Console.WriteLine("| 6. Rotation                | 6_Rotation.cs              |");
                Console.WriteLine("| 7. Serialization           | 7_Serialization.cs         |");
                Console.WriteLine("| 8. Performance Test        | 8_Performance.cs           |");
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
                    Console.Write("> Run example (1 ~ 8) or exit (0): ");
                    key = Console.ReadKey();
                    Console.WriteLine();
                } while (key.KeyChar < '0' || key.KeyChar > '8');
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
                        ExampleBGVBasics();
                        break;

                    case ConsoleKey.D5:
                        ExampleCKKSBasics();
                        break;

                    case ConsoleKey.D6:
                        ExampleRotation();
                        break;

                    case ConsoleKey.D7:
                        ExampleSerialization();
                        break;

                    case ConsoleKey.D8:
                        ExamplePerformanceTest();
                        break;

                    case ConsoleKey.D0:
                        return;

                    default:
                        Console.WriteLine("  [Beep~~] Invalid option: type 0 ~ 8");
                        break;
                }

                /*
                We may want to force a garbage collection after each example to ensure
                all native allocations are released back to the Microsoft SEAL memory pool.
                */
                GC.Collect();
            }
        }
    }
}
