// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

using System;
using Microsoft.Research.SEAL;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;

namespace SEALNetExamples
{
    partial class Examples
    {
        private static void BFVPerformanceTest(SEALContext context)
        {
            Stopwatch timer;
            Utilities.PrintParameters(context);
            Console.WriteLine();

            EncryptionParameters parms = context.FirstContextData.Parms;
            SmallModulus plainModulus = parms.PlainModulus;
            ulong polyModulusDegree = parms.PolyModulusDegree;

            Console.Write("Generating secret/public keys: ");
            KeyGenerator keygen = new KeyGenerator(context);
            Console.WriteLine("Done");

            SecretKey secretKey = keygen.SecretKey;
            PublicKey publicKey = keygen.PublicKey;

            RelinKeys relinKeys = null;
            GaloisKeys galKeys = null;
            if (context.UsingKeyswitching)
            {
                /*
                Generate relinearization keys.
                */
                Console.Write("Generating relinearization keys: ");
                timer = Stopwatch.StartNew();
                relinKeys = keygen.RelinKeys();
                int micros = (int)(timer.Elapsed.TotalMilliseconds * 1000);
                Console.WriteLine($"Done [{micros} microseconds]");

                if (!context.KeyContextData.Qualifiers.UsingBatching)
                {
                    Console.WriteLine("Given encryption parameters do not support batching.");
                    return;
                }

                /*
                Generate Galois keys. In larger examples the Galois keys can use a lot of
                memory, which can be a problem in constrained systems. The user should
                try some of the larger runs of the test and observe their effect on the
                memory pool allocation size. The key generation can also take a long time,
                as can be observed from the print-out.
                */
                Console.Write($"Generating Galois keys: ");
                timer = Stopwatch.StartNew();
                galKeys = keygen.GaloisKeys();
                micros = (int)(timer.Elapsed.TotalMilliseconds * 1000);
                Console.WriteLine($"Done [{micros} microseconds]");
            }

            Encryptor encryptor = new Encryptor(context, publicKey);
            Decryptor decryptor = new Decryptor(context, secretKey);
            Evaluator evaluator = new Evaluator(context);
            BatchEncoder batchEncoder = new BatchEncoder(context);
            IntegerEncoder encoder = new IntegerEncoder(context);

            /*
            These will hold the total times used by each operation.
            */
            Stopwatch timeBatchSum = new Stopwatch();
            Stopwatch timeUnbatchSum = new Stopwatch();
            Stopwatch timeEncryptSum = new Stopwatch();
            Stopwatch timeDecryptSum = new Stopwatch();
            Stopwatch timeAddSum = new Stopwatch();
            Stopwatch timeMultiplySum = new Stopwatch();
            Stopwatch timeMultiplyPlainSum = new Stopwatch();
            Stopwatch timeSquareSum = new Stopwatch();
            Stopwatch timeRelinearizeSum = new Stopwatch();
            Stopwatch timeRotateRowsOneStepSum = new Stopwatch();
            Stopwatch timeRotateRowsRandomSum = new Stopwatch();
            Stopwatch timeRotateColumnsSum = new Stopwatch();

            /*
            How many times to run the test?
            */
            int count = 10;

            /*
            Populate a vector of values to batch.
            */
            ulong slotCount = batchEncoder.SlotCount;
            ulong[] podValues = new ulong[slotCount];
            Random rnd = new Random();
            for (ulong i = 0; i < batchEncoder.SlotCount; i++)
            {
                podValues[i] = (ulong)rnd.Next() % plainModulus.Value;
            }

            Console.Write("Running tests ");
            for (int i = 0; i < count; i++)
            {
                /*
                [Batching]
                There is nothing unusual here. We batch our random plaintext matrix
                into the polynomial. Note how the plaintext we create is of the exactly
                right size so unnecessary reallocations are avoided.
                */
                Plaintext plain = new Plaintext(parms.PolyModulusDegree, 0);
                timeBatchSum.Start();
                batchEncoder.Encode(podValues, plain);
                timeBatchSum.Stop();

                /*
                [Unbatching]
                We unbatch what we just batched.
                */
                List<ulong> podList = new List<ulong>((int)slotCount);
                timeUnbatchSum.Start();
                batchEncoder.Decode(plain, podList);
                timeUnbatchSum.Stop();
                if (!podList.SequenceEqual(podValues))
                {
                    throw new InvalidOperationException("Batch/unbatch failed. Something is wrong.");
                }

                /*
                [Encryption]
                We make sure our ciphertext is already allocated and large enough
                to hold the encryption with these encryption parameters. We encrypt
                our random batched matrix here.
                */
                Ciphertext encrypted = new Ciphertext(context);
                timeEncryptSum.Start();
                encryptor.Encrypt(plain, encrypted);
                timeEncryptSum.Stop();

                /*
                [Decryption]
                We decrypt what we just encrypted.
                */
                Plaintext plain2 = new Plaintext(polyModulusDegree, 0);
                timeDecryptSum.Start();
                decryptor.Decrypt(encrypted, plain2);
                timeDecryptSum.Stop();
                if (!plain2.Equals(plain))
                {
                    throw new InvalidOperationException("Encrypt/decrypt failed. Something is wrong.");
                }

                /*
                [Add]
                We create two ciphertexts and perform a few additions with them.
                */
                Ciphertext encrypted1 = new Ciphertext(context);
                encryptor.Encrypt(encoder.Encode(i), encrypted1);
                Ciphertext encrypted2 = new Ciphertext(context);
                encryptor.Encrypt(encoder.Encode(i + 1), encrypted2);

                timeAddSum.Start();
                evaluator.AddInplace(encrypted1, encrypted1);
                evaluator.AddInplace(encrypted2, encrypted2);
                evaluator.AddInplace(encrypted1, encrypted2);
                timeAddSum.Stop();

                /*
                [Multiply]
                We multiply two ciphertexts. Since the size of the result will be 3,
                and will overwrite the first argument, we reserve first enough memory
                to avoid reallocating during multiplication.
                */
                encrypted1.Reserve(3);
                timeMultiplySum.Start();
                evaluator.MultiplyInplace(encrypted1, encrypted2);
                timeMultiplySum.Stop();

                /*
                [Multiply Plain]
                We multiply a ciphertext with a random plaintext. Recall that
                MultiplyPlain does not change the size of the ciphertext so we use
                encrypted2 here.
                */
                timeMultiplyPlainSum.Start();
                evaluator.MultiplyPlainInplace(encrypted2, plain);
                timeMultiplyPlainSum.Stop();

                /*
                [Square]
                We continue to use encrypted2. Now we square it; this should be
                faster than generic homomorphic multiplication.
                */
                timeSquareSum.Start();
                evaluator.SquareInplace(encrypted2);
                timeSquareSum.Stop();

                if (context.UsingKeyswitching)
                {
                    /*
                    [Relinearize]
                    Time to get back to encrypted1. We now relinearize it back
                    to size 2. Since the allocation is currently big enough to
                    contain a ciphertext of size 3, no costly reallocations are
                    needed in the process.
                    */
                    timeRelinearizeSum.Start();
                    evaluator.RelinearizeInplace(encrypted1, relinKeys);
                    timeRelinearizeSum.Stop();

                    /*
                    [Rotate Rows One Step]
                    We rotate matrix rows by one step left and measure the time.
                    */
                    timeRotateRowsOneStepSum.Start();
                    evaluator.RotateRowsInplace(encrypted, 1, galKeys);
                    evaluator.RotateRowsInplace(encrypted, -1, galKeys);
                    timeRotateRowsOneStepSum.Stop();

                    /*
                    [Rotate Rows Random]
                    We rotate matrix rows by a random number of steps. This is much more
                    expensive than rotating by just one step.
                    */
                    int rowSize = (int)batchEncoder.SlotCount / 2;
                    int randomRotation = rnd.Next() % rowSize;
                    timeRotateRowsRandomSum.Start();
                    evaluator.RotateRowsInplace(encrypted, randomRotation, galKeys);
                    timeRotateRowsRandomSum.Stop();

                    /*
                    [Rotate Columns]
                    Nothing surprising here.
                    */
                    timeRotateColumnsSum.Start();
                    evaluator.RotateColumnsInplace(encrypted, galKeys);
                    timeRotateColumnsSum.Stop();
                }


                /*
                Print a dot to indicate progress.
                */
                Console.Write(".");
                Console.Out.Flush();
            }

            Console.WriteLine(" Done");
            Console.WriteLine();
            Console.Out.Flush();

            int avgBatch = (int)(timeBatchSum.Elapsed.TotalMilliseconds * 1000 / count);
            int avgUnbatch = (int)(timeUnbatchSum.Elapsed.TotalMilliseconds * 1000 / count);
            int avgEncrypt = (int)(timeEncryptSum.Elapsed.TotalMilliseconds * 1000 / count);
            int avgDecrypt = (int)(timeDecryptSum.Elapsed.TotalMilliseconds * 1000 / count);
            int avgAdd = (int)(timeAddSum.Elapsed.TotalMilliseconds * 1000 / (3 * count));
            int avgMultiply = (int)(timeMultiplySum.Elapsed.TotalMilliseconds * 1000 / count);
            int avgMultiplyPlain = (int)(timeMultiplyPlainSum.Elapsed.TotalMilliseconds * 1000 / count);
            int avgSquare = (int)(timeSquareSum.Elapsed.TotalMilliseconds * 1000 / count);
            int avgRelinearize = (int)(timeRelinearizeSum.Elapsed.TotalMilliseconds * 1000 / count);
            int avgRotateRowsOneStep = (int)(timeRotateRowsOneStepSum.Elapsed.TotalMilliseconds * 1000 / (2 * count));
            int avgRotateRowsRandom = (int)(timeRotateRowsRandomSum.Elapsed.TotalMilliseconds * 1000 / count);
            int avgRotateColumns = (int)(timeRotateColumnsSum.Elapsed.TotalMilliseconds * 1000 / count);

            Console.WriteLine($"Average batch: {avgBatch} microseconds");
            Console.WriteLine($"Average unbatch: {avgUnbatch} microseconds");
            Console.WriteLine($"Average encrypt: {avgEncrypt} microseconds");
            Console.WriteLine($"Average decrypt: {avgDecrypt} microseconds");
            Console.WriteLine($"Average add: {avgAdd} microseconds");
            Console.WriteLine($"Average multiply: {avgMultiply} microseconds");
            Console.WriteLine($"Average multiply plain: {avgMultiplyPlain} microseconds");
            Console.WriteLine($"Average square: {avgSquare} microseconds");
            if (context.UsingKeyswitching)
            {
                Console.WriteLine($"Average relinearize: {avgRelinearize} microseconds");
                Console.WriteLine($"Average rotate rows one step: {avgRotateRowsOneStep} microseconds");
                Console.WriteLine($"Average rotate rows random: {avgRotateRowsRandom} microseconds");
                Console.WriteLine($"Average rotate columns: {avgRotateColumns} microseconds");
            }
            Console.Out.Flush();
        }

        private static void CKKSPerformanceTest(SEALContext context)
        {
            Stopwatch timer;
            Utilities.PrintParameters(context);
            Console.WriteLine();

            EncryptionParameters parms = context.FirstContextData.Parms;
            ulong polyModulusDegree = parms.PolyModulusDegree;

            Console.Write("Generating secret/public keys: ");
            KeyGenerator keygen = new KeyGenerator(context);
            Console.WriteLine("Done");

            SecretKey secretKey = keygen.SecretKey;
            PublicKey publicKey = keygen.PublicKey;

            RelinKeys relinKeys = null;
            GaloisKeys galKeys = null;
            if (context.UsingKeyswitching)
            {
                /*
                Generate relinearization keys.
                */
                Console.Write("Generating relinearization keys: ");
                timer = Stopwatch.StartNew();
                relinKeys = keygen.RelinKeys();
                int micros = (int)(timer.Elapsed.TotalMilliseconds * 1000);
                Console.WriteLine($"Done [{micros} microseconds]");

                if (!context.KeyContextData.Qualifiers.UsingBatching)
                {
                    Console.WriteLine("Given encryption parameters do not support batching.");
                    return;
                }

                /*
                Generate Galois keys. In larger examples the Galois keys can use a lot of
                memory, which can be a problem in constrained systems. The user should
                try some of the larger runs of the test and observe their effect on the
                memory pool allocation size. The key generation can also take a long time,
                as can be observed from the print-out.
                */
                Console.Write($"Generating Galois keys: ");
                timer = Stopwatch.StartNew();
                galKeys = keygen.GaloisKeys();
                micros = (int)(timer.Elapsed.TotalMilliseconds * 1000);
                Console.WriteLine($"Done [{micros} microseconds]");
            }

            Encryptor encryptor = new Encryptor(context, publicKey);
            Decryptor decryptor = new Decryptor(context, secretKey);
            Evaluator evaluator = new Evaluator(context);
            CKKSEncoder ckksEncoder = new CKKSEncoder(context);

            Stopwatch timeEncodeSum = new Stopwatch();
            Stopwatch timeDecodeSum = new Stopwatch();
            Stopwatch timeEncryptSum = new Stopwatch();
            Stopwatch timeDecryptSum = new Stopwatch();
            Stopwatch timeAddSum = new Stopwatch();
            Stopwatch timeMultiplySum = new Stopwatch();
            Stopwatch timeMultiplyPlainSum = new Stopwatch();
            Stopwatch timeSquareSum = new Stopwatch();
            Stopwatch timeRelinearizeSum = new Stopwatch();
            Stopwatch timeRescaleSum = new Stopwatch();
            Stopwatch timeRotateOneStepSum = new Stopwatch();
            Stopwatch timeRotateRandomSum = new Stopwatch();
            Stopwatch timeConjugateSum = new Stopwatch();

            Random rnd = new Random();

            /*
            How many times to run the test?
            */
            int count = 10;

            /*
            Populate a vector of floating-point values to batch.
            */
            ulong slotCount = ckksEncoder.SlotCount;
            double[] podValues = new double[slotCount];
            for (ulong i = 0; i < slotCount; i++)
            {
                podValues[i] = 1.001 * i;
            }

            Console.Write("Running tests ");
            for (int i = 0; i < count; i++)
            {
                /*
                [Encoding]
                For scale we use the square root of the last CoeffModulus prime
                from parms.
                */
                double scale = Math.Sqrt(parms.CoeffModulus.Last().Value);
                Plaintext plain = new Plaintext(parms.PolyModulusDegree *
                    (ulong)parms.CoeffModulus.Count(), 0);
                timeEncodeSum.Start();
                ckksEncoder.Encode(podValues, scale, plain);
                timeEncodeSum.Stop();

                /*
                [Decoding]
                */
                List<double> podList = new List<double>((int)slotCount);
                timeDecodeSum.Start();
                ckksEncoder.Decode(plain, podList);
                timeDecodeSum.Stop();

                /*
                [Encryption]
                */
                Ciphertext encrypted = new Ciphertext(context);
                timeEncryptSum.Start();
                encryptor.Encrypt(plain, encrypted);
                timeEncryptSum.Stop();

                /*
                [Decryption]
                */
                Plaintext plain2 = new Plaintext(polyModulusDegree, 0);
                timeDecryptSum.Start();
                decryptor.Decrypt(encrypted, plain2);
                timeDecryptSum.Stop();

                /*
                [Add]
                */
                Ciphertext encrypted1 = new Ciphertext(context);
                ckksEncoder.Encode(i + 1, plain);
                encryptor.Encrypt(plain, encrypted1);
                Ciphertext encrypted2 = new Ciphertext(context);
                ckksEncoder.Encode(i + 1, plain2);
                encryptor.Encrypt(plain2, encrypted2);
                timeAddSum.Start();
                evaluator.AddInplace(encrypted1, encrypted2);
                evaluator.AddInplace(encrypted2, encrypted2);
                evaluator.AddInplace(encrypted1, encrypted2);
                timeAddSum.Stop();

                /*
                [Multiply]
                */
                encrypted1.Reserve(3);
                timeMultiplySum.Start();
                evaluator.MultiplyInplace(encrypted1, encrypted2);
                timeMultiplySum.Stop();

                /*
                [Multiply Plain]
                */
                timeMultiplyPlainSum.Start();
                evaluator.MultiplyPlainInplace(encrypted2, plain);
                timeMultiplyPlainSum.Stop();

                /*
                [Square]
                */
                timeSquareSum.Start();
                evaluator.SquareInplace(encrypted2);
                timeSquareSum.Stop();

                if (context.UsingKeyswitching)
                {
                    /*
                    [Relinearize]
                    */
                    timeRelinearizeSum.Start();
                    evaluator.RelinearizeInplace(encrypted1, relinKeys);
                    timeRelinearizeSum.Stop();

                    /*
                    [Rescale]
                    */
                    timeRescaleSum.Start();
                    evaluator.RescaleToNextInplace(encrypted1);
                    timeRescaleSum.Stop();

                    /*
                    [Rotate Vector]
                    */
                    timeRotateOneStepSum.Start();
                    evaluator.RotateVectorInplace(encrypted, 1, galKeys);
                    evaluator.RotateVectorInplace(encrypted, -1, galKeys);
                    timeRotateOneStepSum.Stop();

                    /*
                    [Rotate Vector Random]
                    */
                    int randomRotation = rnd.Next() % (int)ckksEncoder.SlotCount;
                    timeRotateRandomSum.Start();
                    evaluator.RotateVectorInplace(encrypted, randomRotation, galKeys);
                    timeRotateRandomSum.Stop();

                    /*
                    [Complex Conjugate]
                    */
                    timeConjugateSum.Start();
                    evaluator.ComplexConjugateInplace(encrypted, galKeys);
                    timeConjugateSum.Stop();
                }

                /*
                Print a dot to indicate progress.
                */
                Console.Write(".");
                Console.Out.Flush();
            }

            Console.WriteLine(" Done");
            Console.WriteLine();
            Console.Out.Flush();

            int avgEncode = (int)(timeEncodeSum.Elapsed.TotalMilliseconds * 1000 / count);
            int avgDecode = (int)(timeDecodeSum.Elapsed.TotalMilliseconds * 1000 / count);
            int avgEncrypt = (int)(timeEncryptSum.Elapsed.TotalMilliseconds * 1000 / count);
            int avgDecrypt = (int)(timeDecryptSum.Elapsed.TotalMilliseconds * 1000 / count);
            int avgAdd = (int)(timeAddSum.Elapsed.TotalMilliseconds * 1000 / (3 * count));
            int avgMultiply = (int)(timeMultiplySum.Elapsed.TotalMilliseconds * 1000 / count);
            int avgMultiplyPlain = (int)(timeMultiplyPlainSum.Elapsed.TotalMilliseconds * 1000 / count);
            int avgSquare = (int)(timeSquareSum.Elapsed.TotalMilliseconds * 1000 / count);
            int avgRelinearize = (int)(timeRelinearizeSum.Elapsed.TotalMilliseconds * 1000 / count);
            int avgRescale = (int)(timeRescaleSum.Elapsed.TotalMilliseconds * 1000 / count);
            int avgRotateOneStep = (int)(timeRotateOneStepSum.Elapsed.TotalMilliseconds * 1000 / (2 * count));
            int avgRotateRandom = (int)(timeRotateRandomSum.Elapsed.TotalMilliseconds * 1000 / count);
            int avgConjugate = (int)(timeConjugateSum.Elapsed.TotalMilliseconds * 1000 / count);

            Console.WriteLine($"Average encode: {avgEncode} microseconds");
            Console.WriteLine($"Average decode: {avgDecode} microseconds");
            Console.WriteLine($"Average encrypt: {avgEncrypt} microseconds");
            Console.WriteLine($"Average decrypt: {avgDecrypt} microseconds");
            Console.WriteLine($"Average add: {avgAdd} microseconds");
            Console.WriteLine($"Average multiply: {avgMultiply} microseconds");
            Console.WriteLine($"Average multiply plain: {avgMultiplyPlain} microseconds");
            Console.WriteLine($"Average square: {avgSquare} microseconds");
            if (context.UsingKeyswitching)
            {
                Console.WriteLine($"Average relinearize: {avgRelinearize} microseconds");
                Console.WriteLine($"Average rescale: {avgRescale} microseconds");
                Console.WriteLine($"Average rotate vector one step: {avgRotateOneStep} microseconds");
                Console.WriteLine($"Average rotate vector random: {avgRotateRandom} microseconds");
                Console.WriteLine($"Average complex conjugate: {avgConjugate} microseconds");
            }
            Console.Out.Flush();
        }

        private static void ExampleBFVPerformanceDefault()
        {
            Utilities.PrintExampleBanner("BFV Performance Test with Degrees: 4096, 8192, and 16384");

            EncryptionParameters parms = new EncryptionParameters(SchemeType.BFV);
            ulong polyModulusDegree = 4096;
            parms.PolyModulusDegree = polyModulusDegree;
            parms.CoeffModulus = CoeffModulus.BFVDefault(polyModulusDegree);
            parms.PlainModulus = new SmallModulus(786433);
            BFVPerformanceTest(new SEALContext(parms));

            Console.WriteLine();
            polyModulusDegree = 8192;
            parms.PolyModulusDegree = polyModulusDegree;
            parms.CoeffModulus = CoeffModulus.BFVDefault(polyModulusDegree);
            parms.PlainModulus = new SmallModulus(786433);
            BFVPerformanceTest(new SEALContext(parms));

            Console.WriteLine();
            polyModulusDegree = 16384;
            parms.PolyModulusDegree = polyModulusDegree;
            parms.CoeffModulus = CoeffModulus.BFVDefault(polyModulusDegree);
            parms.PlainModulus = new SmallModulus(786433);
            BFVPerformanceTest(new SEALContext(parms));

            /*
            Comment out the following to run the biggest example.
            */
            //Console.WriteLine();
            //polyModulusDegree = 32768;
            //parms.PolyModulusDegree = polyModulusDegree;
            //parms.CoeffModulus = CoeffModulus.BFVDefault(polyModulusDegree);
            //parms.PlainModulus = new SmallModulus(786433);
            //BFVPerformanceTest(new SEALContext(parms));
        }

        private static void ExampleBFVPerformanceCustom()
        {
            Console.Write("> Set PolyModulusDegree (1024, 2048, 4096, 8192, 16384, or 32768): ");
            string input = Console.ReadLine();
            if (!ulong.TryParse(input, out ulong polyModulusDegree))
            {
                Console.WriteLine("Invalid option.");
                return;
            }
            if (polyModulusDegree < 1024 || polyModulusDegree > 32768 ||
                (polyModulusDegree & (polyModulusDegree - 1)) != 0)
            {
                Console.WriteLine("Invalid option.");
                return;
            }

            string banner = $"BFV Performance Test with Degree: {polyModulusDegree}";
            Utilities.PrintExampleBanner(banner);

            EncryptionParameters parms = new EncryptionParameters(SchemeType.BFV)
            {
                PolyModulusDegree = polyModulusDegree,
                CoeffModulus = CoeffModulus.BFVDefault(polyModulusDegree)
            };
            if (polyModulusDegree == 1024)
            {
                parms.PlainModulus = new SmallModulus(12289);
            }
            else
            {
                parms.PlainModulus = new SmallModulus(786433);
            }
            BFVPerformanceTest(new SEALContext(parms));
        }

        private static void ExampleCKKSPerformanceDefault()
        {
            Utilities.PrintExampleBanner("CKKS Performance Test with Degrees: 4096, 8192, and 16384");

            // It is not recommended to use BFVDefault primes in CKKS. However, for performance
            // test, BFVDefault primes are good enough.
            EncryptionParameters parms = new EncryptionParameters(SchemeType.CKKS);
            ulong polyModulusDegree = 4096;
            parms.PolyModulusDegree = polyModulusDegree;
            parms.CoeffModulus = CoeffModulus.BFVDefault(polyModulusDegree);
            CKKSPerformanceTest(new SEALContext(parms));

            Console.WriteLine();
            polyModulusDegree = 8192;
            parms.PolyModulusDegree = polyModulusDegree;
            parms.CoeffModulus = CoeffModulus.BFVDefault(polyModulusDegree);
            CKKSPerformanceTest(new SEALContext(parms));

            Console.WriteLine();
            polyModulusDegree = 16384;
            parms.PolyModulusDegree = polyModulusDegree;
            parms.CoeffModulus = CoeffModulus.BFVDefault(polyModulusDegree);
            CKKSPerformanceTest(new SEALContext(parms));

            /*
            Comment out the following to run the biggest example.
            */
            //Console.WriteLine();
            //polyModulusDegree = 32768;
            //parms.PolyModulusDegree = polyModulusDegree;
            //parms.CoeffModulus = CoeffModulus.BFVDefault(polyModulusDegree);
            //CKKSPerformanceTest(new SEALContext(parms));
        }

        private static void ExampleCKKSPerformanceCustom()
        {
            Console.Write("> Set PolyModulusDegree (1024, 2048, 4096, 8192, 16384, or 32768): ");
            string input = Console.ReadLine();
            if (!ulong.TryParse(input, out ulong polyModulusDegree))
            {
                Console.WriteLine("Invalid option.");
                return;
            }
            if (polyModulusDegree < 1024 || polyModulusDegree > 32768 ||
                (polyModulusDegree & (polyModulusDegree - 1)) != 0)
            {
                Console.WriteLine("Invalid option.");
                return;
            }

            string banner = $"CKKS Performance Test with Degree: {polyModulusDegree}";
            Utilities.PrintExampleBanner(banner);

            EncryptionParameters parms = new EncryptionParameters(SchemeType.CKKS)
            {
                PolyModulusDegree = polyModulusDegree,
                CoeffModulus = CoeffModulus.BFVDefault(polyModulusDegree)
            };
            CKKSPerformanceTest(new SEALContext(parms));
        }

        private static void ExamplePerformanceTest()
        {
            Utilities.PrintExampleBanner("Example: Performance Test");

            if (!Stopwatch.IsHighResolution)
            {
                Console.WriteLine("WARNING: High resolution stopwatch not available in this machine.");
                Console.WriteLine("         Timings might not be accurate.");
            }

            while (true)
            {
                Console.WriteLine();
                Console.WriteLine("Select a scheme (and optionally PolyModulusDegree):");
                Console.WriteLine("  1. BFV with default degrees");
                Console.WriteLine("  2. BFV with a custom degree");
                Console.WriteLine("  3. CKKS with default degrees");
                Console.WriteLine("  4. CKKS with a custom degree");
                Console.WriteLine("  0. Back to main menu");
                Console.WriteLine();

                ConsoleKeyInfo key;
                do
                {
                    Console.Write("> Run performance test (1 ~ 4) or go back (0): ");
                    key = Console.ReadKey();
                    Console.WriteLine();
                } while (key.KeyChar < '0' || key.KeyChar > '4');
                switch (key.Key)
                {
                    case ConsoleKey.D1:
                        ExampleBFVPerformanceDefault();
                        break;

                    case ConsoleKey.D2:
                        ExampleBFVPerformanceCustom();
                        break;

                    case ConsoleKey.D3:
                        ExampleCKKSPerformanceDefault();
                        break;

                    case ConsoleKey.D4:
                        ExampleCKKSPerformanceCustom();
                        break;

                    case ConsoleKey.D0:
                        Console.WriteLine();
                        return;

                    default:
                        Console.WriteLine("  [Beep~~] Invalid option: type 0 ~ 4");
                        break;
                }
            }
        }
    }
}
