// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using Microsoft.Research.SEAL;

namespace SEALNetExamples
{
    partial class Examples
    {
        private static void BFVPerformanceTest(SEALContext context)
        {
            Stopwatch timer;
            Utilities.PrintParameters(context);
            Console.WriteLine();

            bool hasZLIB = Serialization.IsSupportedComprMode(ComprModeType.ZLIB);
            bool hasZSTD = Serialization.IsSupportedComprMode(ComprModeType.ZSTD);

            using EncryptionParameters parms = context.FirstContextData.Parms;
            using Modulus plainModulus = parms.PlainModulus;
            ulong polyModulusDegree = parms.PolyModulusDegree;

            Console.Write("Generating secret/public keys: ");
            using KeyGenerator keygen = new KeyGenerator(context);
            Console.WriteLine("Done");

            using SecretKey secretKey = keygen.SecretKey;
            keygen.CreatePublicKey(out PublicKey publicKey);

            Func<RelinKeys> GetRelinKeys = () => {
                if (context.UsingKeyswitching)
                {
                    /*
                    Generate relinearization keys.
                    */
                    Console.Write("Generating relinearization keys: ");
                    timer = Stopwatch.StartNew();
                    keygen.CreateRelinKeys(out RelinKeys relinKeys);
                    int micros = (int)(timer.Elapsed.TotalMilliseconds * 1000);
                    Console.WriteLine($"Done [{micros} microseconds]");
                    return relinKeys;
                }
                else
                {
                    return null;
                }
            };

            Func<GaloisKeys> GetGaloisKeys = () => {
                if (context.UsingKeyswitching)
                {
                    if (!context.KeyContextData.Qualifiers.UsingBatching)
                    {
                        Console.WriteLine("Given encryption parameters do not support batching.");
                        return null;
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
                    keygen.CreateGaloisKeys(out GaloisKeys galoisKeys);
                    int micros = (int)(timer.Elapsed.TotalMilliseconds * 1000);
                    Console.WriteLine($"Done [{micros} microseconds]");
                    return galoisKeys;
                }
                else
                {
                    return null;
                }
            };

            using RelinKeys relinKeys = GetRelinKeys();
            using GaloisKeys galKeys = GetGaloisKeys();

            using Encryptor encryptor = new Encryptor(context, publicKey);
            using Decryptor decryptor = new Decryptor(context, secretKey);
            using Evaluator evaluator = new Evaluator(context);
            using BatchEncoder batchEncoder = new BatchEncoder(context);

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
            Stopwatch timeSerializeSum = new Stopwatch();
            Stopwatch timeSerializeZLIBSum = new Stopwatch();
            Stopwatch timeSerializeZSTDSum = new Stopwatch();

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
                podValues[i] = plainModulus.Reduce((ulong)rnd.Next());
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
                using Plaintext plain = new Plaintext(parms.PolyModulusDegree, 0);
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
                using Ciphertext encrypted = new Ciphertext(context);
                timeEncryptSum.Start();
                encryptor.Encrypt(plain, encrypted);
                timeEncryptSum.Stop();

                /*
                [Decryption]
                We decrypt what we just encrypted.
                */
                using Plaintext plain2 = new Plaintext(polyModulusDegree, 0);
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
                using Plaintext plain1 = new Plaintext(parms.PolyModulusDegree, 0);
                for (ulong j = 0; j < batchEncoder.SlotCount; j++)
                {
                    podValues[j] = j;
                }
                batchEncoder.Encode(podValues, plain1);
                for (ulong j = 0; j < batchEncoder.SlotCount; j++)
                {
                    podValues[j] = j + 1;
                }
                batchEncoder.Encode(podValues, plain2);
                using Ciphertext encrypted1 = new Ciphertext(context);
                encryptor.Encrypt(plain1, encrypted1);
                using Ciphertext encrypted2 = new Ciphertext(context);
                encryptor.Encrypt(plain2, encrypted2);

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
                    // rowSize is always a power of 2.
                    int randomRotation = rnd.Next() & (rowSize - 1);
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
                [Serialize Ciphertext]
                */
                using MemoryStream stream = new MemoryStream();
                timeSerializeSum.Start();
                encrypted.Save(stream, ComprModeType.None);
                timeSerializeSum.Stop();

                if (hasZLIB)
                {
                    /*
                    [Serialize Ciphertext (ZLIB)]
                    */
                    timeSerializeZLIBSum.Start();
                    encrypted.Save(stream, ComprModeType.ZLIB);
                    timeSerializeZLIBSum.Stop();
                }

                if (hasZSTD)
                {
                    /*
                    [Serialize Ciphertext (Zstandard)]
                    */
                    timeSerializeZSTDSum.Start();
                    encrypted.Save(stream, ComprModeType.ZSTD);
                    timeSerializeZSTDSum.Stop();
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
            int avgSerializeSum = (int)(timeSerializeSum.Elapsed.TotalMilliseconds * 1000 / count);
            int avgSerializeZLIBSum = (int)(timeSerializeZLIBSum.Elapsed.TotalMilliseconds * 1000 / count);
            int avgSerializeZSTDSum = (int)(timeSerializeZSTDSum.Elapsed.TotalMilliseconds * 1000 / count);

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
            Console.WriteLine($"Average serialize ciphertext: {avgSerializeSum} microseconds");
            if (hasZLIB)
            {
                Console.WriteLine(
                    $"Average compressed (ZLIB) serialize ciphertext: {avgSerializeZLIBSum} microseconds");
            }
            if (hasZSTD)
            {
                Console.WriteLine(
                    $"Average compressed (Zstandard) serialize ciphertext: {avgSerializeZSTDSum} microseconds");
            }

            Console.Out.Flush();
        }

        private static void CKKSPerformanceTest(SEALContext context)
        {
            Stopwatch timer;
            Utilities.PrintParameters(context);
            Console.WriteLine();

            bool hasZLIB = Serialization.IsSupportedComprMode(ComprModeType.ZLIB);
            bool hasZSTD = Serialization.IsSupportedComprMode(ComprModeType.ZSTD);

            using EncryptionParameters parms = context.FirstContextData.Parms;
            ulong polyModulusDegree = parms.PolyModulusDegree;

            Console.Write("Generating secret/public keys: ");
            using KeyGenerator keygen = new KeyGenerator(context);
            Console.WriteLine("Done");

            using SecretKey secretKey = keygen.SecretKey;
            keygen.CreatePublicKey(out PublicKey publicKey);

            Func<RelinKeys> GetRelinKeys = () => {
                if (context.UsingKeyswitching)
                {
                    /*
                    Generate relinearization keys.
                    */
                    Console.Write("Generating relinearization keys: ");
                    timer = Stopwatch.StartNew();
                    keygen.CreateRelinKeys(out RelinKeys relinKeys);
                    int micros = (int)(timer.Elapsed.TotalMilliseconds * 1000);
                    Console.WriteLine($"Done [{micros} microseconds]");
                    return relinKeys;
                }
                else
                {
                    return null;
                }
            };

            Func<GaloisKeys> GetGaloisKeys = () => {
                if (context.UsingKeyswitching)
                {
                    if (!context.KeyContextData.Qualifiers.UsingBatching)
                    {
                        Console.WriteLine("Given encryption parameters do not support batching.");
                        return null;
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
                    keygen.CreateGaloisKeys(out GaloisKeys galoisKeys);
                    int micros = (int)(timer.Elapsed.TotalMilliseconds * 1000);
                    Console.WriteLine($"Done [{micros} microseconds]");
                    return galoisKeys;
                }
                else
                {
                    return null;
                }
            };

            using RelinKeys relinKeys = GetRelinKeys();
            using GaloisKeys galKeys = GetGaloisKeys();

            using Encryptor encryptor = new Encryptor(context, publicKey);
            using Decryptor decryptor = new Decryptor(context, secretKey);
            using Evaluator evaluator = new Evaluator(context);
            using CKKSEncoder ckksEncoder = new CKKSEncoder(context);

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
            Stopwatch timeSerializeSum = new Stopwatch();
            Stopwatch timeSerializeZLIBSum = new Stopwatch();
            Stopwatch timeSerializeZSTDSum = new Stopwatch();

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
                using Plaintext plain = new Plaintext(parms.PolyModulusDegree *
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
                using Ciphertext encrypted = new Ciphertext(context);
                timeEncryptSum.Start();
                encryptor.Encrypt(plain, encrypted);
                timeEncryptSum.Stop();

                /*
                [Decryption]
                */
                using Plaintext plain2 = new Plaintext(polyModulusDegree, 0);
                timeDecryptSum.Start();
                decryptor.Decrypt(encrypted, plain2);
                timeDecryptSum.Stop();

                /*
                [Add]
                */
                using Ciphertext encrypted1 = new Ciphertext(context);
                ckksEncoder.Encode(i + 1, plain);
                encryptor.Encrypt(plain, encrypted1);
                using Ciphertext encrypted2 = new Ciphertext(context);
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
                    // ckksEncoder.SlotCount is always a power of 2.
                    int randomRotation = rnd.Next() & ((int)ckksEncoder.SlotCount - 1);
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
                [Serialize Ciphertext]
                */
                using MemoryStream stream = new MemoryStream();
                timeSerializeSum.Start();
                encrypted.Save(stream, ComprModeType.None);
                timeSerializeSum.Stop();

                if (hasZLIB)
                {
                    /*
                    [Serialize Ciphertext (ZLIB)]
                    */
                    timeSerializeZLIBSum.Start();
                    encrypted.Save(stream, ComprModeType.ZLIB);
                    timeSerializeZLIBSum.Stop();
                }

                if (hasZSTD)
                {
                    /*
                    [Serialize Ciphertext (Zstandard)]
                    */
                    timeSerializeZSTDSum.Start();
                    encrypted.Save(stream, ComprModeType.ZSTD);
                    timeSerializeZSTDSum.Stop();
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
            int avgSerializeSum = (int)(timeSerializeSum.Elapsed.TotalMilliseconds * 1000 / count);
            int avgSerializeZLIBSum = (int)(timeSerializeZLIBSum.Elapsed.TotalMilliseconds * 1000 / count);
            int avgSerializeZSTDSum = (int)(timeSerializeZSTDSum.Elapsed.TotalMilliseconds * 1000 / count);

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
            Console.WriteLine($"Average serialize ciphertext: {avgSerializeSum} microseconds");
            if (hasZLIB)
            {
                Console.WriteLine(
                    $"Average compressed (ZLIB) serialize ciphertext: {avgSerializeZLIBSum} microseconds");
            }
            if (hasZSTD)
            {
                Console.WriteLine(
                    $"Average compressed (Zstandard) serialize ciphertext: {avgSerializeZSTDSum} microseconds");
            }

            Console.Out.Flush();
        }

        private static void BGVPerformanceTest(SEALContext context)
        {
            Stopwatch timer;
            Utilities.PrintParameters(context);
            Console.WriteLine();

            bool hasZLIB = Serialization.IsSupportedComprMode(ComprModeType.ZLIB);
            bool hasZSTD = Serialization.IsSupportedComprMode(ComprModeType.ZSTD);

            using EncryptionParameters parms = context.FirstContextData.Parms;
            using Modulus plainModulus = parms.PlainModulus;
            ulong polyModulusDegree = parms.PolyModulusDegree;

            Console.Write("Generating secret/public keys: ");
            using KeyGenerator keygen = new KeyGenerator(context);
            Console.WriteLine("Done");

            using SecretKey secretKey = keygen.SecretKey;
            keygen.CreatePublicKey(out PublicKey publicKey);

            Func<RelinKeys> GetRelinKeys = () => {
                if (context.UsingKeyswitching)
                {
                    /*
                    Generate relinearization keys.
                    */
                    Console.Write("Generating relinearization keys: ");
                    timer = Stopwatch.StartNew();
                    keygen.CreateRelinKeys(out RelinKeys relinKeys);
                    int micros = (int)(timer.Elapsed.TotalMilliseconds * 1000);
                    Console.WriteLine($"Done [{micros} microseconds]");
                    return relinKeys;
                }
                else
                {
                    return null;
                }
            };

            Func<GaloisKeys> GetGaloisKeys = () => {
                if (context.UsingKeyswitching)
                {
                    if (!context.KeyContextData.Qualifiers.UsingBatching)
                    {
                        Console.WriteLine("Given encryption parameters do not support batching.");
                        return null;
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
                    keygen.CreateGaloisKeys(out GaloisKeys galoisKeys);
                    int micros = (int)(timer.Elapsed.TotalMilliseconds * 1000);
                    Console.WriteLine($"Done [{micros} microseconds]");
                    return galoisKeys;
                }
                else
                {
                    return null;
                }
            };

            using RelinKeys relinKeys = GetRelinKeys();
            using GaloisKeys galKeys = GetGaloisKeys();

            using Encryptor encryptor = new Encryptor(context, publicKey);
            using Decryptor decryptor = new Decryptor(context, secretKey);
            using Evaluator evaluator = new Evaluator(context);
            using BatchEncoder batchEncoder = new BatchEncoder(context);

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
            Stopwatch timeSerializeSum = new Stopwatch();
            Stopwatch timeSerializeZLIBSum = new Stopwatch();
            Stopwatch timeSerializeZSTDSum = new Stopwatch();

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
                podValues[i] = plainModulus.Reduce((ulong)rnd.Next());
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
                using Plaintext plain = new Plaintext(parms.PolyModulusDegree, 0);
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
                using Ciphertext encrypted = new Ciphertext(context);
                timeEncryptSum.Start();
                encryptor.Encrypt(plain, encrypted);
                timeEncryptSum.Stop();

                /*
                [Decryption]
                We decrypt what we just encrypted.
                */
                using Plaintext plain2 = new Plaintext(polyModulusDegree, 0);
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
                using Plaintext plain1 = new Plaintext(parms.PolyModulusDegree, 0);
                for (ulong j = 0; j < batchEncoder.SlotCount; j++)
                {
                    podValues[j] = j;
                }
                batchEncoder.Encode(podValues, plain1);
                for (ulong j = 0; j < batchEncoder.SlotCount; j++)
                {
                    podValues[j] = j + 1;
                }
                batchEncoder.Encode(podValues, plain2);
                using Ciphertext encrypted1 = new Ciphertext(context);
                encryptor.Encrypt(plain1, encrypted1);
                using Ciphertext encrypted2 = new Ciphertext(context);
                encryptor.Encrypt(plain2, encrypted2);

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
                    // rowSize is always a power of 2.
                    int randomRotation = rnd.Next() & (rowSize - 1);
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
                [Serialize Ciphertext]
                */
                using MemoryStream stream = new MemoryStream();
                timeSerializeSum.Start();
                encrypted.Save(stream, ComprModeType.None);
                timeSerializeSum.Stop();

                if (hasZLIB)
                {
                    /*
                    [Serialize Ciphertext (ZLIB)]
                    */
                    timeSerializeZLIBSum.Start();
                    encrypted.Save(stream, ComprModeType.ZLIB);
                    timeSerializeZLIBSum.Stop();
                }

                if (hasZSTD)
                {
                    /*
                    [Serialize Ciphertext (Zstandard)]
                    */
                    timeSerializeZSTDSum.Start();
                    encrypted.Save(stream, ComprModeType.ZSTD);
                    timeSerializeZSTDSum.Stop();
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
            int avgSerializeSum = (int)(timeSerializeSum.Elapsed.TotalMilliseconds * 1000 / count);
            int avgSerializeZLIBSum = (int)(timeSerializeZLIBSum.Elapsed.TotalMilliseconds * 1000 / count);
            int avgSerializeZSTDSum = (int)(timeSerializeZSTDSum.Elapsed.TotalMilliseconds * 1000 / count);

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
            Console.WriteLine($"Average serialize ciphertext: {avgSerializeSum} microseconds");
            if (hasZLIB)
            {
                Console.WriteLine(
                    $"Average compressed (ZLIB) serialize ciphertext: {avgSerializeZLIBSum} microseconds");
            }
            if (hasZSTD)
            {
                Console.WriteLine(
                    $"Average compressed (Zstandard) serialize ciphertext: {avgSerializeZSTDSum} microseconds");
            }

            Console.Out.Flush();
        }

        private static void ExampleBFVPerformanceDefault()
        {
            Utilities.PrintExampleBanner("BFV Performance Test with Degrees: 4096, 8192, and 16384");

            using EncryptionParameters parms = new EncryptionParameters(SchemeType.BFV);
            ulong polyModulusDegree = 4096;
            parms.PolyModulusDegree = polyModulusDegree;
            parms.CoeffModulus = CoeffModulus.BFVDefault(polyModulusDegree);
            parms.PlainModulus = new Modulus(786433);
            using (SEALContext context = new SEALContext(parms))
            {
                BFVPerformanceTest(context);
            }

            Console.WriteLine();
            polyModulusDegree = 8192;
            parms.PolyModulusDegree = polyModulusDegree;
            parms.CoeffModulus = CoeffModulus.BFVDefault(polyModulusDegree);
            parms.PlainModulus = new Modulus(786433);
            using (SEALContext context = new SEALContext(parms))
            {
                BFVPerformanceTest(context);
            }

            Console.WriteLine();
            polyModulusDegree = 16384;
            parms.PolyModulusDegree = polyModulusDegree;
            parms.CoeffModulus = CoeffModulus.BFVDefault(polyModulusDegree);
            parms.PlainModulus = new Modulus(786433);
            using (SEALContext context = new SEALContext(parms))
            {
                BFVPerformanceTest(context);
            }

            /*
            Comment out the following to run the biggest example.
            */
            //Console.WriteLine();
            //polyModulusDegree = 32768;
            //parms.PolyModulusDegree = polyModulusDegree;
            //parms.CoeffModulus = CoeffModulus.BFVDefault(polyModulusDegree);
            //parms.PlainModulus = new Modulus(786433);
            //using (SEALContext context = new SEALContext(parms))
            //{
            //    BFVPerformanceTest(context);
            //}
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

            using EncryptionParameters parms = new EncryptionParameters(SchemeType.BFV)
            {
                PolyModulusDegree = polyModulusDegree,
                CoeffModulus = CoeffModulus.BFVDefault(polyModulusDegree)
            };
            if (polyModulusDegree == 1024)
            {
                parms.PlainModulus = new Modulus(12289);
            }
            else
            {
                parms.PlainModulus = new Modulus(786433);
            }

            using (SEALContext context = new SEALContext(parms))
            {
                BFVPerformanceTest(context);
            }
        }

        private static void ExampleCKKSPerformanceDefault()
        {
            Utilities.PrintExampleBanner("CKKS Performance Test with Degrees: 4096, 8192, and 16384");

            // It is not recommended to use BFVDefault primes in CKKS. However, for performance
            // test, BFVDefault primes are good enough.
            using EncryptionParameters parms = new EncryptionParameters(SchemeType.CKKS);
            ulong polyModulusDegree = 4096;
            parms.PolyModulusDegree = polyModulusDegree;
            parms.CoeffModulus = CoeffModulus.BFVDefault(polyModulusDegree);
            using (SEALContext context = new SEALContext(parms))
            {
                CKKSPerformanceTest(context);
            }

            Console.WriteLine();
            polyModulusDegree = 8192;
            parms.PolyModulusDegree = polyModulusDegree;
            parms.CoeffModulus = CoeffModulus.BFVDefault(polyModulusDegree);
            using (SEALContext context = new SEALContext(parms))
            {
                CKKSPerformanceTest(context);
            }

            Console.WriteLine();
            polyModulusDegree = 16384;
            parms.PolyModulusDegree = polyModulusDegree;
            parms.CoeffModulus = CoeffModulus.BFVDefault(polyModulusDegree);
            using (SEALContext context = new SEALContext(parms))
            {
                CKKSPerformanceTest(context);
            }

            /*
            Comment out the following to run the biggest example.
            */
            //Console.WriteLine();
            //polyModulusDegree = 32768;
            //parms.PolyModulusDegree = polyModulusDegree;
            //parms.CoeffModulus = CoeffModulus.BFVDefault(polyModulusDegree);
            //using (SEALContext context = new SEALContext(parms))
            //{
            //    CKKSPerformanceTest(context);
            //}
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

            using EncryptionParameters parms = new EncryptionParameters(SchemeType.CKKS)
            {
                PolyModulusDegree = polyModulusDegree,
                CoeffModulus = CoeffModulus.BFVDefault(polyModulusDegree)
            };

            using (SEALContext context = new SEALContext(parms))
            {
                CKKSPerformanceTest(context);
            }
        }

        private static void ExampleBGVPerformanceDefault()
        {
            Utilities.PrintExampleBanner("BGV Performance Test with Degrees: 4096, 8192, and 16384");

            using EncryptionParameters parms = new EncryptionParameters(SchemeType.BGV);
            ulong polyModulusDegree = 4096;
            parms.PolyModulusDegree = polyModulusDegree;
            parms.CoeffModulus = CoeffModulus.BFVDefault(polyModulusDegree);
            parms.PlainModulus = new Modulus(786433);
            using (SEALContext context = new SEALContext(parms))
            {
                BGVPerformanceTest(context);
            }

            Console.WriteLine();
            polyModulusDegree = 8192;
            parms.PolyModulusDegree = polyModulusDegree;
            parms.CoeffModulus = CoeffModulus.BFVDefault(polyModulusDegree);
            parms.PlainModulus = new Modulus(786433);
            using (SEALContext context = new SEALContext(parms))
            {
                BGVPerformanceTest(context);
            }

            Console.WriteLine();
            polyModulusDegree = 16384;
            parms.PolyModulusDegree = polyModulusDegree;
            parms.CoeffModulus = CoeffModulus.BFVDefault(polyModulusDegree);
            parms.PlainModulus = new Modulus(786433);
            using (SEALContext context = new SEALContext(parms))
            {
                BGVPerformanceTest(context);
            }

            /*
            Comment out the following to run the biggest example.
            */
            //Console.WriteLine();
            //polyModulusDegree = 32768;
            //parms.PolyModulusDegree = polyModulusDegree;
            //parms.CoeffModulus = CoeffModulus.BFVDefault(polyModulusDegree);
            //parms.PlainModulus = new Modulus(786433);
            //using (SEALContext context = new SEALContext(parms))
            //{
            //    BGVPerformanceTest(context);
            //}
        }

        private static void ExampleBGVPerformanceCustom()
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

            string banner = $"BGV Performance Test with Degree: {polyModulusDegree}";
            Utilities.PrintExampleBanner(banner);

            using EncryptionParameters parms = new EncryptionParameters(SchemeType.BGV)
            {
                PolyModulusDegree = polyModulusDegree,
                CoeffModulus = CoeffModulus.BFVDefault(polyModulusDegree)
            };
            if (polyModulusDegree == 1024)
            {
                parms.PlainModulus = new Modulus(12289);
            }
            else
            {
                parms.PlainModulus = new Modulus(786433);
            }

            using (SEALContext context = new SEALContext(parms))
            {
                BGVPerformanceTest(context);
            }
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
                Console.WriteLine("  5. BGV with default degrees");
                Console.WriteLine("  6. BGV with a custom degree");
                Console.WriteLine("  0. Back to main menu");
                Console.WriteLine();

                ConsoleKeyInfo key;
                do
                {
                    Console.Write("> Run performance test (1 ~ 6) or go back (0): ");
                    key = Console.ReadKey();
                    Console.WriteLine();
                } while (key.KeyChar < '0' || key.KeyChar > '6');
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

                    case ConsoleKey.D5:
                        ExampleBGVPerformanceDefault();
                        break;

                    case ConsoleKey.D6:
                        ExampleBGVPerformanceCustom();
                        break;

                    case ConsoleKey.D0:
                        Console.WriteLine();
                        return;

                    default:
                        Console.WriteLine("  [Beep~~] Invalid option: type 0 ~ 6");
                        break;
                }
            }
        }
    }
}
