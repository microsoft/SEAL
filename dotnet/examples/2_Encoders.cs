// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

using System;
using System.Collections.Generic;
using Microsoft.Research.SEAL;

namespace SEALNetExamples
{
    partial class Examples
    {
        /*
        In `1_BFV_Basics.cs' we showed how to perform a very simple computation using the
        BFV scheme. The computation was performed modulo the PlainModulus parameter, and
        utilized only one coefficient from a BFV plaintext polynomial. This approach has
        two notable problems:

            (1) Practical applications typically use integer or real number arithmetic,
                not modular arithmetic;
            (2) We used only one coefficient of the plaintext polynomial. This is really
                wasteful, as the plaintext polynomial is large and will in any case be
                encrypted in its entirety.

        For (1), one may ask why not just increase the PlainModulus parameter until no
        overflow occurs, and the computations behave as in integer arithmetic. The problem
        is that increasing PlainModulus increases noise budget consumption, and decreases
        the initial noise budget too.

        In these examples we will discuss other ways of laying out data into plaintext
        elements (encoding) that allow more computations without data type overflow, and
        can allow the full plaintext polynomial to be utilized.
        */
        private static void ExampleIntegerEncoder()
        {
            Utilities.PrintExampleBanner("Example: Encoders / Integer Encoder");

            /*
            [IntegerEncoder] (For BFV scheme only)

            The IntegerEncoder encodes integers to BFV plaintext polynomials as follows.
            First, a binary expansion of the integer is computed. Next, a polynomial is
            created with the bits as coefficients. For example, the integer

                26 = 2^4 + 2^3 + 2^1

            is encoded as the polynomial 1x^4 + 1x^3 + 1x^1. Conversely, plaintext
            polynomials are decoded by evaluating them at x=2. For negative numbers the
            IntegerEncoder simply stores all coefficients as either 0 or -1, where -1 is
            represented by the unsigned integer PlainModulus - 1 in memory.

            Since encrypted computations operate on the polynomials rather than on the
            encoded integers themselves, the polynomial coefficients will grow in the
            course of such computations. For example, computing the sum of the encrypted
            encoded integer 26 with itself will result in an encrypted polynomial with
            larger coefficients: 2x^4 + 2x^3 + 2x^1. Squaring the encrypted encoded
            integer 26 results also in increased coefficients due to cross-terms, namely,

                (1x^4 + 1x^3 + 1x^1)^2 = 1x^8 + 2x^7 + 1x^6 + 2x^5 + 2x^4 + 1x^2;

            further computations will quickly increase the coefficients much more.
            Decoding will still work correctly in this case (evaluating the polynomial
            at x=2), but since the coefficients of plaintext polynomials are really
            integers modulo plain_modulus, implicit reduction modulo plain_modulus may
            yield unexpected results. For example, adding 1x^4 + 1x^3 + 1x^1 to itself
            plain_modulus many times will result in the constant polynomial 0, which is
            clearly not equal to 26 * plain_modulus. It can be difficult to predict when
            such overflow will take place especially when computing several sequential
            multiplications.

            The IntegerEncoder is easy to understand and use for simple computations,
            and can be a good tool to experiment with for users new to Microsoft SEAL.
            However, advanced users will probably prefer more efficient approaches,
            such as the BatchEncoder or the CKKSEncoder.
            */
            EncryptionParameters parms = new EncryptionParameters(SchemeType.BFV);
            ulong polyModulusDegree = 4096;
            parms.PolyModulusDegree = polyModulusDegree;
            parms.CoeffModulus = CoeffModulus.BFVDefault(polyModulusDegree);

            /*
            There is no hidden logic behind our choice of the plain_modulus. The only
            thing that matters is that the plaintext polynomial coefficients will not
            exceed this value at any point during our computation; otherwise the result
            will be incorrect.
            */
            parms.PlainModulus = new SmallModulus(512);
            SEALContext context = new SEALContext(parms);
            Utilities.PrintParameters(context);
            Console.WriteLine();

            KeyGenerator keygen = new KeyGenerator(context);
            PublicKey publicKey = keygen.PublicKey;
            SecretKey secretKey = keygen.SecretKey;
            Encryptor encryptor = new Encryptor(context, publicKey);
            Evaluator evaluator = new Evaluator(context);
            Decryptor decryptor = new Decryptor(context, secretKey);

            /*
            We create an IntegerEncoder.
            */
            IntegerEncoder encoder = new IntegerEncoder(context);

            /*
            First, we encode two integers as plaintext polynomials. Note that encoding
            is not encryption: at this point nothing is encrypted.
            */
            int value1 = 5;
            Plaintext plain1 = encoder.Encode(value1);
            Utilities.PrintLine();
            Console.WriteLine($"Encode {value1} as polynomial {plain1} (plain1),");

            int value2 = -7;
            Plaintext plain2 = encoder.Encode(value2);
            Console.WriteLine(new string(' ', 13)
                + $"Encode {value2} as polynomial {plain2} (plain2),");

            /*
            Now we can encrypt the plaintext polynomials.
            */
            Ciphertext encrypted1 = new Ciphertext();
            Ciphertext encrypted2 = new Ciphertext();
            Utilities.PrintLine();
            Console.WriteLine("Encrypt plain1 to encrypted1 and plain2 to encrypted2.");
            encryptor.Encrypt(plain1, encrypted1);
            encryptor.Encrypt(plain2, encrypted2);
            Console.WriteLine("    + Noise budget in encrypted1: {0} bits",
                decryptor.InvariantNoiseBudget(encrypted1));
            Console.WriteLine("    + Noise budget in encrypted2: {0} bits",
                decryptor.InvariantNoiseBudget(encrypted2));

            /*
            As a simple example, we compute (-encrypted1 + encrypted2) * encrypted2.
            */
            encryptor.Encrypt(plain2, encrypted2);
            Ciphertext encryptedResult = new Ciphertext();
            Utilities.PrintLine();
            Console.WriteLine("Compute encrypted_result = (-encrypted1 + encrypted2) * encrypted2.");
            evaluator.Negate(encrypted1, encryptedResult);
            evaluator.AddInplace(encryptedResult, encrypted2);
            evaluator.MultiplyInplace(encryptedResult, encrypted2);
            Console.WriteLine("    + Noise budget in encryptedResult: {0} bits",
                decryptor.InvariantNoiseBudget(encryptedResult));

            Plaintext plainResult = new Plaintext();
            Utilities.PrintLine();
            Console.WriteLine("Decrypt encrypted_result to plain_result.");
            decryptor.Decrypt(encryptedResult, plainResult);

            /*
            Print the result plaintext polynomial. The coefficients are not even close
            to exceeding our plainModulus, 512.
            */
            Console.WriteLine($"    + Plaintext polynomial: {plainResult}");

            /*
            Decode to obtain an integer result.
            */
            Utilities.PrintLine();
            Console.WriteLine("Decode plain_result.");
            Console.WriteLine("    + Decoded integer: {0} ...... Correct.",
                encoder.DecodeInt32(plainResult));
        }

        private static void ExampleBatchEncoder()
        {
            Utilities.PrintExampleBanner("Example: Encoders / Batch Encoder");

            /*
            [BatchEncoder] (For BFV scheme only)

            Let N denote the PolyModulusDegree and T denote the PlainModulus. Batching
            allows the BFV plaintext polynomials to be viewed as 2-by-(N/2) matrices, with
            each element an integer modulo T. In the matrix view, encrypted operations act
            element-wise on encrypted matrices, allowing the user to obtain speeds-ups of
            several orders of magnitude in fully vectorizable computations. Thus, in all
            but the simplest computations, batching should be the preferred method to use
            with BFV, and when used properly will result in implementations outperforming
            anything done with the IntegerEncoder.
            */
            EncryptionParameters parms = new EncryptionParameters(SchemeType.BFV);
            ulong polyModulusDegree = 8192;
            parms.PolyModulusDegree = polyModulusDegree;
            parms.CoeffModulus = CoeffModulus.BFVDefault(polyModulusDegree);

            /*
            To enable batching, we need to set the plain_modulus to be a prime number
            congruent to 1 modulo 2*PolyModulusDegree. Microsoft SEAL provides a helper
            method for finding such a prime. In this example we create a 20-bit prime
            that supports batching.
            */
            parms.PlainModulus = PlainModulus.Batching(polyModulusDegree, 20);

            SEALContext context = new SEALContext(parms);
            Utilities.PrintParameters(context);
            Console.WriteLine();

            /*
            We can verify that batching is indeed enabled by looking at the encryption
            parameter qualifiers created by SEALContext.
            */
            var qualifiers = context.FirstContextData.Qualifiers;
            Console.WriteLine($"Batching enabled: {qualifiers.UsingBatching}");

            KeyGenerator keygen = new KeyGenerator(context);
            PublicKey publicKey = keygen.PublicKey;
            SecretKey secretKey = keygen.SecretKey;
            RelinKeys relinKeys = keygen.RelinKeys();
            Encryptor encryptor = new Encryptor(context, publicKey);
            Evaluator evaluator = new Evaluator(context);
            Decryptor decryptor = new Decryptor(context, secretKey);

            /*
            Batching is done through an instance of the BatchEncoder class.
            */
            BatchEncoder batchEncoder = new BatchEncoder(context);

            /*
            The total number of batching `slots' equals the PolyModulusDegree, N, and
            these slots are organized into 2-by-(N/2) matrices that can be encrypted and
            computed on. Each slot contains an integer modulo PlainModulus.
            */
            ulong slotCount = batchEncoder.SlotCount;
            ulong rowSize = slotCount / 2;
            Console.WriteLine($"Plaintext matrix row size: {rowSize}");

            /*
            The matrix plaintext is simply given to BatchEncoder as a flattened vector
            of numbers. The first `rowSize' many numbers form the first row, and the
            rest form the second row. Here we create the following matrix:

                [ 0,  1,  2,  3,  0,  0, ...,  0 ]
                [ 4,  5,  6,  7,  0,  0, ...,  0 ]
            */
            ulong[] podMatrix = new ulong[slotCount];
            podMatrix[0] = 0;
            podMatrix[1] = 1;
            podMatrix[2] = 2;
            podMatrix[3] = 3;
            podMatrix[rowSize] = 4;
            podMatrix[rowSize + 1] = 5;
            podMatrix[rowSize + 2] = 6;
            podMatrix[rowSize + 3] = 7;

            Console.WriteLine("Input plaintext matrix:");
            Utilities.PrintMatrix(podMatrix, (int)rowSize);

            /*
            First we use BatchEncoder to encode the matrix into a plaintext polynomial.
            */
            Plaintext plainMatrix = new Plaintext();
            Utilities.PrintLine();
            Console.WriteLine("Encode plaintext matrix:");
            batchEncoder.Encode(podMatrix, plainMatrix);

            /*
            We can instantly decode to verify correctness of the encoding. Note that no
            encryption or decryption has yet taken place.
            */
            List<ulong> podResult = new List<ulong>();
            Console.WriteLine("    + Decode plaintext matrix ...... Correct.");
            batchEncoder.Decode(plainMatrix, podResult);
            Utilities.PrintMatrix(podResult, (int)rowSize);

            /*
            Next we encrypt the encoded plaintext.
            */
            Ciphertext encryptedMatrix = new Ciphertext();
            Utilities.PrintLine();
            Console.WriteLine("Encrypt plainMatrix to encryptedMatrix.");
            encryptor.Encrypt(plainMatrix, encryptedMatrix);
            Console.WriteLine("    + Noise budget in encryptedMatrix: {0} bits",
                decryptor.InvariantNoiseBudget(encryptedMatrix));

            /*
            Operating on the ciphertext results in homomorphic operations being performed
            simultaneously in all 8192 slots (matrix elements). To illustrate this, we
            form another plaintext matrix

                [ 1,  2,  1,  2,  1,  2, ..., 2 ]
                [ 1,  2,  1,  2,  1,  2, ..., 2 ]

            and encode it into a plaintext.
            */
            ulong[] podMatrix2 = new ulong[slotCount];
            for (ulong i = 0; i < slotCount; i++)
            {
                podMatrix2[i] = (i % 2) + 1;
            }
            Plaintext plainMatrix2 = new Plaintext();
            batchEncoder.Encode(podMatrix2, plainMatrix2);
            Console.WriteLine();
            Console.WriteLine("Second input plaintext matrix:");
            Utilities.PrintMatrix(podMatrix2, (int)rowSize);

            /*
            We now add the second (plaintext) matrix to the encrypted matrix, and square
            the sum.
            */
            Utilities.PrintLine();
            Console.WriteLine("Sum, square, and relinearize.");
            evaluator.AddPlainInplace(encryptedMatrix, plainMatrix2);
            evaluator.SquareInplace(encryptedMatrix);
            evaluator.RelinearizeInplace(encryptedMatrix, relinKeys);

            /*
            How much noise budget do we have left?
            */
            Console.WriteLine("    + Noise budget in result: {0} bits",
                decryptor.InvariantNoiseBudget(encryptedMatrix));

            /*
            We decrypt and decompose the plaintext to recover the result as a matrix.
            */
            Plaintext plainResult = new Plaintext();
            Utilities.PrintLine();
            Console.WriteLine("Decrypt and decode result.");
            decryptor.Decrypt(encryptedMatrix, plainResult);
            batchEncoder.Decode(plainResult, podResult);
            Console.WriteLine("    + Result plaintext matrix ...... Correct.");
            Utilities.PrintMatrix(podResult, (int)rowSize);

            /*
            Batching allows us to efficiently use the full plaintext polynomial when the
            desired encrypted computation is highly parallelizable. However, it has not
            solved the other problem mentioned in the beginning of this file: each slot
            holds only an integer modulo plain_modulus, and unless plain_modulus is very
            large, we can quickly encounter data type overflow and get unexpected results
            when integer computations are desired. Note that overflow cannot be detected
            in encrypted form. The CKKS scheme (and the CKKSEncoder) addresses the data
            type overflow issue, but at the cost of yielding only approximate results.
            */
        }

        static private void ExampleCKKSEncoder()
        {
            Utilities.PrintExampleBanner("Example: Encoders / CKKS Encoder");

            /*
            [CKKSEncoder] (For CKKS scheme only)

            In this example we demonstrate the Cheon-Kim-Kim-Song (CKKS) scheme for
            computing on encrypted real or complex numbers. We start by creating
            encryption parameters for the CKKS scheme. There are two important
            differences compared to the BFV scheme:

                (1) CKKS does not use the PlainModulus encryption parameter;
                (2) Selecting the CoeffModulus in a specific way can be very important
                    when using the CKKS scheme. We will explain this further in the file
                    `CKKS_Basics.cs'. In this example we use CoeffModulus.Create to
                    generate 5 40-bit prime numbers.
            */
            EncryptionParameters parms = new EncryptionParameters(SchemeType.CKKS);

            ulong polyModulusDegree = 8192;
            parms.PolyModulusDegree = polyModulusDegree;
            parms.CoeffModulus = CoeffModulus.Create(
                polyModulusDegree, new int[]{ 40, 40, 40, 40, 40 });

            /*
            We create the SEALContext as usual and print the parameters.
            */
            SEALContext context = new SEALContext(parms);
            Utilities.PrintParameters(context);
            Console.WriteLine();

            /*
            Keys are created the same way as for the BFV scheme.
            */
            KeyGenerator keygen = new KeyGenerator(context);
            PublicKey publicKey = keygen.PublicKey;
            SecretKey secretKey = keygen.SecretKey;
            RelinKeys relinKeys = keygen.RelinKeys();

            /*
            We also set up an Encryptor, Evaluator, and Decryptor as usual.
            */
            Encryptor encryptor = new Encryptor(context, publicKey);
            Evaluator evaluator = new Evaluator(context);
            Decryptor decryptor = new Decryptor(context, secretKey);

            /*
            To create CKKS plaintexts we need a special encoder: there is no other way
            to create them. The IntegerEncoder and BatchEncoder cannot be used with the
            CKKS scheme. The CKKSEncoder encodes vectors of real or complex numbers into
            Plaintext objects, which can subsequently be encrypted. At a high level this
            looks a lot like what BatchEncoder does for the BFV scheme, but the theory
            behind it is completely different.
            */
            CKKSEncoder encoder = new CKKSEncoder(context);

            /*
            In CKKS the number of slots is PolyModulusDegree / 2 and each slot encodes
            one real or complex number. This should be contrasted with BatchEncoder in
            the BFV scheme, where the number of slots is equal to PolyModulusDegree
            and they are arranged into a matrix with two rows.
            */
            ulong slotCount = encoder.SlotCount;
            Console.WriteLine($"Number of slots: {slotCount}");

            /*
            We create a small vector to encode; the CKKSEncoder will implicitly pad it
            with zeros to full size (PolyModulusDegree / 2) when encoding.
            */
            double[] input = new double[]{ 0.0, 1.1, 2.2, 3.3 };
            Console.WriteLine("Input vector: ");
            Utilities.PrintVector(input);

            /*
            Now we encode it with CKKSEncoder. The floating-point coefficients of `input'
            will be scaled up by the parameter `scale'. This is necessary since even in
            the CKKS scheme the plaintext elements are fundamentally polynomials with
            integer coefficients. It is instructive to think of the scale as determining
            the bit-precision of the encoding; naturally it will affect the precision of
            the result.

            In CKKS the message is stored modulo CoeffModulus (in BFV it is stored modulo
            PlainModulus), so the scaled message must not get too close to the total size
            of CoeffModulus. In this case our CoeffModulus is quite large (218 bits) so
            we have little to worry about in this regard. For this simple example a 30-bit
            scale is more than enough.
            */
            Plaintext plain = new Plaintext();
            double scale = Math.Pow(2.0, 30);
            Utilities.PrintLine();
            Console.WriteLine("Encode input vector.");
            encoder.Encode(input, scale, plain);

            /*
            We can instantly decode to check the correctness of encoding.
            */
            List<double> output = new List<double>();
            Console.WriteLine("    + Decode input vector ...... Correct.");
            encoder.Decode(plain, output);
            Utilities.PrintVector(output);

            /*
            The vector is encrypted the same was as in BFV.
            */
            Ciphertext encrypted = new Ciphertext();
            Utilities.PrintLine();
            Console.WriteLine("Encrypt input vector, square, and relinearize.");
            encryptor.Encrypt(plain, encrypted);

            /*
            Basic operations on the ciphertexts are still easy to do. Here we square
            the ciphertext, decrypt, decode, and print the result. We note also that
            decoding returns a vector of full size (PolyModulusDegree / 2); this is
            because of the implicit zero-padding mentioned above.
            */
            evaluator.SquareInplace(encrypted);
            evaluator.RelinearizeInplace(encrypted, relinKeys);

            /*
            We notice that the scale in the result has increased. In fact, it is now
            the square of the original scale: 2^60.
            */
            Console.WriteLine("    + Scale in squared input: {0} ({1} bits)",
                encrypted.Scale,
                (int)Math.Ceiling(Math.Log(encrypted.Scale, newBase: 2)));
            Utilities.PrintLine();
            Console.WriteLine("Decrypt and decode.");
            decryptor.Decrypt(encrypted, plain);
            encoder.Decode(plain, output);
            Console.WriteLine("    + Result vector ...... Correct.");
            Utilities.PrintVector(output);

            /*
            The CKKS scheme allows the scale to be reduced between encrypted computations.
            This is a fundamental and critical feature that makes CKKS very powerful and
            flexible. We will discuss it in great detail in `3_Levels.cs' and later in
            `4_CKKS_Basics.cs'.
            */
        }

        private static void ExampleEncoders()
        {
            Utilities.PrintExampleBanner("Example: Encoders");

            /*
            Run all encoder examples.
            */
            ExampleIntegerEncoder();
            ExampleBatchEncoder();
            ExampleCKKSEncoder();
        }
    }
}
