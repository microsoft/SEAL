// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

using System;
using System.Collections.Generic;
using System.Text;

namespace SEALNetExamples
{
    partial class Examples
    {
        private static void ExampleBFVPerformance()
        {
            Utilities.PrintExampleBanner("Example: BFV Performance Test");

            /*
            In this example we time all the basic operations. We use the following
            local function to run the test.
            */
            void performanceTest(SEALContext context)
            {
                if (!Stopwatch.IsHighResolution)
                {
                    Console.WriteLine("WARNING: High resolution stopwatch not available in this machine.");
                    Console.WriteLine("         Timings might not be accurate.");
                }

                Stopwatch timer;
                Utilities.PrintParameters(context);

                EncryptionParameters parameters = context.FirstContextData.Parms;
                SmallModulus plainModulus = parameters.PlainModulus;
                ulong polyModulusDegree = parameters.PolyModulusDegree;

                /*
                Set up keys. For both relinearization and rotations we use a large
                decomposition bit count for best possible computational performance.
                */
                Console.Write("Generating secret/public keys: ");
                KeyGenerator keygen = new KeyGenerator(context);
                Console.WriteLine("Done");

                SecretKey secretKey = keygen.SecretKey;
                PublicKey publicKey = keygen.PublicKey;

                /*
                Generate relinearization keys.
                */
                int dbc = DefaultParams.DBCmax;
                Console.Write($"Generating relinearization keys (dbc = {dbc}): ");
                timer = Stopwatch.StartNew();
                RelinKeys relinKeys = keygen.RelinKeys(decompositionBitCount: dbc);
                int micros = (int)(timer.Elapsed.TotalMilliseconds * 1000);
                Console.WriteLine($"Done [{micros} microseconds]");

                /*
                Generate Galois keys. In larger examples the Galois keys can use
                a significant amount of memory, which can be a problem in constrained
                systems. The user should try enabling some of the larger runs of the
                test (see below) and to observe their effect on the memory pool
                allocation size. The key generation can also take a significant amount
                of time, as can be observed from the print-out.
                */
                if (!context.FirstContextData.Qualifiers.UsingBatching)
                {
                    Console.WriteLine("Given encryption parameters do not support batching.");
                    return;
                }

                Console.Write($"Generating Galois keys (dbc = {dbc}): ");
                timer = Stopwatch.StartNew();
                GaloisKeys galKeys = keygen.GaloisKeys(decompositionBitCount: dbc);
                micros = (int)(timer.Elapsed.TotalMilliseconds * 1000);
                Console.WriteLine($"Done [{micros} microseconds]");

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
                List<ulong> podList = new List<ulong>();

                Random rnd = new Random();
                for (ulong i = 0; i < batchEncoder.SlotCount; i++)
                {
                    podList.Add((ulong)rnd.Next() % plainModulus.Value);
                }

                Console.Write("Running tests ");
                for (int i = 0; i < count; i++)
                {
                    /*
                    [Batching]
                    There is nothing unusual here. We batch our random plaintext matrix
                    into the polynomial. The user can try changing the decomposition bit
                    count to something smaller to see the effect. Note how the plaintext
                    we create is of the exactly right size so unnecessary reallocations
                    are avoided.
                    */
                    Plaintext plain = new Plaintext(parameters.PolyModulusDegree, 0);
                    timeBatchSum.Start();
                    batchEncoder.Encode(podList, plain);
                    timeBatchSum.Stop();

                    /*
                    [Unbatching]
                    We unbatch what we just batched.
                    */
                    List<ulong> podList2 = new List<ulong>((int)batchEncoder.SlotCount);
                    timeUnbatchSum.Start();
                    batchEncoder.Decode(plain, podList2);
                    timeUnbatchSum.Stop();

                    /*
                    [Encryption]
                    We make sure our ciphertext is already allocated and large enough to
                    hold the encryption with these encryption parameters. We encrypt our
                    random batched matrix here.
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
                    We create two ciphertexts that are both of size 2, and perform a few
                    additions with them.
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
                    We multiply two ciphertexts of size 2. Since the size of the result
                    will be 3, and will overwrite the first argument, we reserve first
                    enough memory to avoid reallocating during multiplication.
                    */
                    encrypted1.Reserve(3);
                    timeMultiplySum.Start();
                    evaluator.MultiplyInplace(encrypted1, encrypted2);
                    timeMultiplySum.Stop();

                    /*
                    [Multiply Plain]
                    We multiply a ciphertext of size 2 with a random plaintext. Recall
                    that MultiplyPlain does not change the size of the ciphertext so we
                    use encrypted2 here, which still has size 2.
                    */
                    timeMultiplyPlainSum.Start();
                    evaluator.MultiplyPlainInplace(encrypted2, plain);
                    timeMultiplyPlainSum.Stop();

                    /*
                    [Square]
                    We continue to use the size 2 ciphertext encrypted2. Now we square
                    it; this should be faster than generic homomorphic multiplication.
                    */
                    timeSquareSum.Start();
                    evaluator.SquareInplace(encrypted2);
                    timeSquareSum.Stop();

                    /*
                    [Relinearize]
                    Time to get back to encrypted1; at this point it still has size 3.
                    We now relinearize it back to size 2. Since the allocation is
                    currently big enough to contain a ciphertext of size 3, no costly
                    reallocations are needed in the process.
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
                    We rotate matrix rows by a random number of steps. This is more
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
                Console.WriteLine($"Average relinearize: {avgRelinearize} microseconds");
                Console.WriteLine($"Average rotate rows one step: {avgRotateRowsOneStep} microseconds");
                Console.WriteLine($"Average rotate rows random: {avgRotateRowsRandom} microseconds");
                Console.WriteLine($"Average rotate columns: {avgRotateColumns} microseconds");
                Console.Out.Flush();
            }


            EncryptionParameters parms = new EncryptionParameters(SchemeType.BFV);
            parms.PolyModulusDegree = 4096;
            parms.CoeffModulus = DefaultParams.CoeffModulus128(polyModulusDegree: 4096);
            parms.SetPlainModulus(786433);
            performanceTest(SEALContext.Create(parms));

            Console.WriteLine();
            parms.PolyModulusDegree = 8192;
            parms.CoeffModulus = DefaultParams.CoeffModulus128(polyModulusDegree: 8192);
            parms.SetPlainModulus(786433);
            performanceTest(SEALContext.Create(parms));

            Console.WriteLine();
            parms.PolyModulusDegree = 16384;
            parms.CoeffModulus = DefaultParams.CoeffModulus128(polyModulusDegree: 16384);
            parms.SetPlainModulus(786433);
            performanceTest(SEALContext.Create(parms));

            /*
            Comment out the following to run the biggest example.
            */
            //Console.WriteLine();
            //parms.PolyModulusDegree = 32768;
            //parms.CoeffModulus = DefaultParams.CoeffModulus128(32768);
            //parms.SetPlainModulus(786433);
            //performanceTest(SEALContext.Create(parms));
        }

        private static void ExampleCKKSPerformance()
        {
            Utilities.PrintExampleBanner("Example: CKKS Performance Test");

            /*
            In this example we time all the basic operations. We use the following
            local function to run the test. This is largely similar to the function
            in the previous example.
            */
            void performanceTest(SEALContext context)
            {
                if (!Stopwatch.IsHighResolution)
                {
                    Console.WriteLine("WARNING: High resolution stopwatch not available in this machine.");
                    Console.WriteLine("         Timings might not be accurate.");
                }

                Utilities.PrintParameters(context);
                EncryptionParameters parms = context.FirstContextData.Parms;
                ulong polyModulusDegree = parms.PolyModulusDegree;

                Console.Write("Generating secret/public keys: ");
                KeyGenerator keygen = new KeyGenerator(context);
                Console.WriteLine("Done");

                SecretKey secretKey = keygen.SecretKey;
                PublicKey publicKey = keygen.PublicKey;

                int dbc = DefaultParams.DBCmax;
                Console.Write($"Generating relinearization keys (dbc = {dbc}): ");
                Stopwatch timer = Stopwatch.StartNew();
                RelinKeys relinKeys = keygen.RelinKeys(dbc);
                timer.Stop();
                Console.WriteLine($"Done [{timer.Elapsed.TotalMilliseconds * 1000} microseconds]");

                if (!context.FirstContextData.Qualifiers.UsingBatching)
                {
                    Console.WriteLine("Given encryption parameters do not support batching.");
                    return;
                }

                Console.Write($"Generating Galois keys (dbc = {dbc}): ");
                timer = Stopwatch.StartNew();
                GaloisKeys galKeys = keygen.GaloisKeys(dbc);
                timer.Stop();
                Console.WriteLine($"Done [{timer.Elapsed.TotalMilliseconds * 1000} microseconds]");

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
                List<double> podList = new List<double>();
                for (ulong i = 0; i < ckksEncoder.SlotCount; i++)
                {
                    podList.Add(1.001 * i);
                }

                Console.Write("Running tests ");

                for (int i = 0; i < count; i++)
                {
                    /*
                    [Encoding]
                    */
                    Plaintext plain = new Plaintext(parms.PolyModulusDegree *
                        (ulong)parms.CoeffModulus.Count(), 0);
                    timeEncodeSum.Start();
                    ckksEncoder.Encode(podList, (double)parms.CoeffModulus.Last().Value, plain);
                    timeEncodeSum.Stop();

                    /*
                    [Decoding]
                    */
                    List<double> podList2 = new List<double>((int)ckksEncoder.SlotCount);
                    timeDecodeSum.Start();
                    ckksEncoder.Decode(plain, podList2);
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
                Console.WriteLine($"Average relinearize: {avgRelinearize} microseconds");
                Console.WriteLine($"Average rescale: {avgRescale} microseconds");
                Console.WriteLine($"Average rotate vector one step: {avgRotateOneStep} microseconds");
                Console.WriteLine($"Average rotate vector random: {avgRotateRandom} microseconds");
                Console.WriteLine($"Average complex conjugate: {avgConjugate} microseconds");
                Console.Out.Flush();
            }

            EncryptionParameters encparms = new EncryptionParameters(SchemeType.CKKS);
            encparms.PolyModulusDegree = 4096;
            encparms.CoeffModulus = DefaultParams.CoeffModulus128(4096);
            performanceTest(SEALContext.Create(encparms));

            Console.WriteLine();
            encparms.PolyModulusDegree = 8192;
            encparms.CoeffModulus = DefaultParams.CoeffModulus128(8192);
            performanceTest(SEALContext.Create(encparms));

            Console.WriteLine();
            encparms.PolyModulusDegree = 16384;
            encparms.CoeffModulus = DefaultParams.CoeffModulus128(16384);
            performanceTest(SEALContext.Create(encparms));

            /*
            Comment out the following to run the biggest example.
            */
            //Console.WriteLine();
            //encparms.PolyModulusDegree = 32768;
            //encparms.CoeffModulus = DefaultParams.CoeffModulus128(32768);
            //performanceTest(SEALContext.Create(encparms));
        }

    }
}
