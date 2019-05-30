// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

using System;
using System.Collections.Generic;
using System.Text;

namespace SEALNetExamples
{
    partial class Examples
    {
        private static void ExampleBFVBasicsIII()
        {
            Utilities.PrintExampleBanner("Example: BFV Basics III");

            /*
            In this fundamental example we discuss and demonstrate a powerful technique
            called `batching'. If N denotes the degree of the polynomial modulus, and T
            the plaintext modulus, then batching is automatically enabled for the BFV
            scheme when T is a prime number congruent to 1 modulo 2*N. In batching the
            plaintexts are viewed as matrices of size 2-by-(N/2) with each element an
            integer modulo T. Homomorphic operations act element-wise between encrypted
            matrices, allowing the user to obtain speeds-ups of several orders of
            magnitude in naively vectorizable computations. We demonstrate two more
            homomorphic operations which act on encrypted matrices by rotating the rows
            cyclically, or rotate the columns (i.e. swap the rows). These operations
            require the construction of so-called `Galois keys', which are very similar
            to relinearization keys.

            The batching functionality is totally optional in the BFV scheme and is
            exposed through the BatchEncoder class.
            */
            EncryptionParameters parms = new EncryptionParameters(SchemeType.BFV);

            parms.PolyModulusDegree = 4096;
            parms.CoeffModulus = DefaultParams.CoeffModulus128(polyModulusDegree: 4096);

            /*
            Note that 40961 is a prime number and 2*4096 divides 40960, so batching will
            automatically be enabled for these parameters.
            */
            parms.SetPlainModulus(40961);

            SEALContext context = SEALContext.Create(parms);
            Utilities.PrintParameters(context);

            /*
            We can verify that batching is indeed enabled by looking at the encryption
            parameter qualifiers created by SEALContext.
            */
            EncryptionParameterQualifiers qualifiers = context.FirstContextData.Qualifiers;
            Console.WriteLine($"Batching enabled: {qualifiers.UsingBatching.ToString()}");

            KeyGenerator keygen = new KeyGenerator(context);
            PublicKey publicKey = keygen.PublicKey;
            SecretKey secretKey = keygen.SecretKey;

            /*
            We need to create so-called `Galois keys' for performing matrix row and
            column rotations on encrypted matrices. Like relinearization keys, the
            behavior of Galois keys depends on a decomposition bit count. The noise
            budget consumption behavior of matrix row and column rotations is exactly
            like that of relinearization (recall ExampleBFVBasicsII()).

            Here we use a moderate size decomposition bit count.
            */
            GaloisKeys galKeys = keygen.GaloisKeys(decompositionBitCount: 30);

            /*
            Since we are going to do some multiplications we will also relinearize.
            */
            RelinKeys relinKeys = keygen.RelinKeys(decompositionBitCount: 30);

            /*
            We also set up an Encryptor, Evaluator, and Decryptor here.
            */
            Encryptor encryptor = new Encryptor(context, publicKey);
            Evaluator evaluator = new Evaluator(context);
            Decryptor decryptor = new Decryptor(context, secretKey);

            /*
            Batching is done through an instance of the BatchEncoder class so need to
            construct one.
            */
            BatchEncoder batchEncoder = new BatchEncoder(context);

            /*
            The total number of batching `slots' is PolyModulusDegree. The matrices
            we encrypt are of size 2-by-(slot_count / 2).
            */
            ulong slotCount = batchEncoder.SlotCount;
            ulong rowSize = slotCount / 2;
            Console.WriteLine($"Plaintext matrix row size: {rowSize}");

            /*
            The matrix plaintext is simply given to BatchEncoder as a flattened vector
            of numbers of size slotCount. The first row_size numbers form the first row,
            and the rest form the second row. Here we create the following matrix:

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
            First we use BatchEncoder to compose the matrix into a plaintext.
            */
            Plaintext plainMatrix = new Plaintext();
            batchEncoder.Encode(podMatrix, plainMatrix);

            /*
            Next we encrypt the plaintext as usual.
            */
            Ciphertext encryptedMatrix = new Ciphertext();
            Console.Write("Encrypting: ");
            encryptor.Encrypt(plainMatrix, encryptedMatrix);
            Console.WriteLine("Done");
            Console.WriteLine($"Noise budget in fresh encryption: {decryptor.InvariantNoiseBudget(encryptedMatrix)} bits");

            /*
            Operating on the ciphertext results in homomorphic operations being performed
            simultaneously in all 4096 slots (matrix elements). To illustrate this, we
            form another plaintext matrix

                [ 1,  2,  1,  2,  1,  2, ..., 2 ]
                [ 1,  2,  1,  2,  1,  2, ..., 2 ]

            and compose it into a plaintext.
            */
            ulong[] podMatrix2 = new ulong[slotCount];
            for (ulong i = 0; i < slotCount; i++)
            {
                podMatrix2[i] = ((i % 2) + 1);
            }
            Plaintext plainMatrix2 = new Plaintext();
            batchEncoder.Encode(podMatrix2, plainMatrix2);
            Console.WriteLine("Second input plaintext matrix:");
            Utilities.PrintMatrix(podMatrix2, (int)rowSize);

            /*
            We now add the second (plaintext) matrix to the encrypted one using another
            new operation -- plain addition -- and square the sum.
            */
            Console.Write("Adding and squaring: ");
            evaluator.AddPlainInplace(encryptedMatrix, plainMatrix2);
            evaluator.SquareInplace(encryptedMatrix);
            evaluator.RelinearizeInplace(encryptedMatrix, relinKeys);
            Console.WriteLine("Done");

            /*
            How much noise budget do we have left?
            */
            Console.WriteLine($"Noise budget in result: {decryptor.InvariantNoiseBudget(encryptedMatrix)} bits");

            /*
            We decrypt and decompose the plaintext to recover the result as a matrix.
            */
            Plaintext plainResult = new Plaintext();
            Console.Write("Decrypting result: ");
            decryptor.Decrypt(encryptedMatrix, plainResult);
            Console.WriteLine("Done");

            List<ulong> podResult = new List<ulong>();
            batchEncoder.Decode(plainResult, podResult);

            Console.WriteLine("Result plaintext matrix:");
            Utilities.PrintMatrix(podResult, (int)rowSize);

            /*
            Note how the operation was performed in one go for each of the elements of
            the matrix. It is possible to achieve incredible performance improvements by
            using this method when the computation is easily vectorizable.

            Our discussion so far could have applied just as well for a simple vector
            data type (not matrix). Now we show how the matrix view of the plaintext can
            be used for more functionality. Namely, it is possible to rotate the matrix
            rows cyclically, and same for the columns (i.e. swap the two rows). For this
            we need the Galois keys that we generated earlier.

            We return to the original matrix that we started with.
            */
            encryptor.Encrypt(plainMatrix, encryptedMatrix);
            Console.WriteLine("Unrotated matrix: ");
            Utilities.PrintMatrix(podMatrix, (int)rowSize);
            Console.WriteLine($"Noise budget in fresh encryption: {decryptor.InvariantNoiseBudget(encryptedMatrix)} bits");

            /*
            Now rotate the rows to the left 3 steps, decrypt, decompose, and print.
            */
            evaluator.RotateRowsInplace(encryptedMatrix, steps: 3, galoisKeys: galKeys);
            Console.WriteLine("Rotated rows 3 steps left: ");
            decryptor.Decrypt(encryptedMatrix, plainResult);
            batchEncoder.Decode(plainResult, podResult);
            Utilities.PrintMatrix(podResult, (int)rowSize);
            Console.WriteLine($"Noise budget after rotation: {decryptor.InvariantNoiseBudget(encryptedMatrix)} bits");

            /*
            Rotate columns (swap rows), decrypt, decompose, and print.
            */
            evaluator.RotateColumnsInplace(encryptedMatrix, galKeys);
            Console.WriteLine("Rotated columns: ");
            decryptor.Decrypt(encryptedMatrix, plainResult);
            batchEncoder.Decode(plainResult, podResult);
            Utilities.PrintMatrix(podResult, (int)rowSize);
            Console.WriteLine($"Noise budget after rotation: {decryptor.InvariantNoiseBudget(encryptedMatrix)} bits");

            /*
            Rotate rows to the right 4 steps, decrypt, decompose, and print.
            */
            evaluator.RotateRowsInplace(encryptedMatrix, steps: -4, galoisKeys: galKeys);
            Console.WriteLine("Rotated rows 4 steps right:");
            decryptor.Decrypt(encryptedMatrix, plainResult);
            batchEncoder.Decode(plainResult, podResult);
            Utilities.PrintMatrix(podResult, (int)rowSize);
            Console.WriteLine($"Noise budget after rotation: {decryptor.InvariantNoiseBudget(encryptedMatrix)} bits");

            /*
            The output is as expected. Note how the noise budget gets a big hit in the
            first rotation, but remains almost unchanged in the next rotations. This is
            again the same phenomenon that occurs with relinearization, where the noise
            budget is consumed down to some bound determined by the decomposition bit
            count and the encryption parameters. For example, after some multiplications
            have been performed rotations come basically for free (noise budget-wise),
            whereas they can be relatively expensive when the noise budget is nearly
            full unless a small decomposition bit count is used, which on the other hand
            is computationally costly.
            */
        }

    }
}
