// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

using System;
using System.Collections.Generic;
using Microsoft.Research.SEAL;

namespace SEALNetExamples
{
    partial class Examples
    {
        private static void ExampleBGVBasics()
        {
            Utilities.PrintExampleBanner("Example: BGV Basics");

            /*
            As an example, we evaluate the degree 8 polynomial

                x^8

            over an encrypted x over integers 1, 2, 3, 4. The coefficients of the
            polynomial can be considered as plaintext inputs, as we will see below. The
            computation is done modulo the plain_modulus 1032193.

            Computing over encrypted data in the BGV scheme is similar to that in BFV.
            The purpose of this example is mainly to explain the differences between BFV
            and BGV in terms of ciphertext coefficient modulus selection and noise control.

            Most of the following code are repeated from "BFV basics" and "encoders" examples.
            */

            /*
            Note that scheme_type is now "bgv".
            */
            using EncryptionParameters parms = new EncryptionParameters(SchemeType.BGV);
            ulong polyModulusDegree = 8192;
            parms.PolyModulusDegree = polyModulusDegree;

            /*
            We can certainly use BFVDefault coeff_modulus. In later parts of this example,
            we will demonstrate how to choose coeff_modulus that is more useful in BGV.
            */
            parms.CoeffModulus = CoeffModulus.BFVDefault(polyModulusDegree);
            parms.PlainModulus = PlainModulus.Batching(polyModulusDegree, 20);
            using SEALContext context = new SEALContext(parms);

            /*
            Print the parameters that we have chosen.
            */
            Utilities.PrintLine();
            Console.WriteLine("Set encryption parameters and print");
            Utilities.PrintParameters(context);

            using KeyGenerator keygen = new KeyGenerator(context);
            using SecretKey secretKey = keygen.SecretKey;
            keygen.CreatePublicKey(out PublicKey publicKey);
            keygen.CreateRelinKeys(out RelinKeys relinKeys);
            using Encryptor encryptor = new Encryptor(context, publicKey);
            using Evaluator evaluator = new Evaluator(context);
            using Decryptor decryptor = new Decryptor(context, secretKey);

            /*
            Batching and slot operations are the same in BFV and BGV.
            */
            using BatchEncoder batchEncoder = new BatchEncoder(context);
            ulong slotCount = batchEncoder.SlotCount;
            ulong rowSize = slotCount / 2;
            Console.WriteLine($"Plaintext matrix row size: {rowSize}");

            /*
            Here we create the following matrix:
                [ 1,  2,  3,  4,  0,  0, ...,  0 ]
                [ 0,  0,  0,  0,  0,  0, ...,  0 ]
            */
            ulong[] podMatrix = new ulong[slotCount];
            podMatrix[0] = 1;
            podMatrix[1] = 2;
            podMatrix[2] = 3;
            podMatrix[3] = 4;

            Console.WriteLine("Input plaintext matrix:");
            Utilities.PrintMatrix(podMatrix, (int)rowSize);
            using Plaintext xPlain = new Plaintext();
            Console.WriteLine("Encode plaintext matrix to xPlain:");
            batchEncoder.Encode(podMatrix, xPlain);

            /*
            Next we encrypt the encoded plaintext.
            */
            using Ciphertext xEncrypted = new Ciphertext();
            Utilities.PrintLine();
            Console.WriteLine("Encrypt xPlain to xEncrypted.");
            encryptor.Encrypt(xPlain, xEncrypted);
            Console.WriteLine("    + noise budget in freshly encrypted x: {0} bits",
                decryptor.InvariantNoiseBudget(xEncrypted));
            Console.WriteLine();

            /*
            Then we compute x^2.
            */
            Utilities.PrintLine();
            Console.WriteLine("Compute and relinearize xSquared (x^2),");
            using Ciphertext xSquared = new Ciphertext();
            evaluator.Square(xEncrypted, xSquared);
            Console.WriteLine($"    + size of xSquared: {xSquared.Size}");
            evaluator.RelinearizeInplace(xSquared, relinKeys);
            Console.WriteLine("    + size of xSquared (after relinearization): {0}",
                xSquared.Size);
            Console.WriteLine("    + noise budget in xSquared: {0} bits",
                decryptor.InvariantNoiseBudget(xSquared));
            using Plaintext decryptedResult = new Plaintext();
            decryptor.Decrypt(xSquared, decryptedResult);
            List<ulong> podResult = new List<ulong>();
            batchEncoder.Decode(decryptedResult, podResult);
            Console.WriteLine("    + result plaintext matrix ...... Correct.");
            Utilities.PrintMatrix(podResult, (int)rowSize);

            /*
            Next we compute x^4.
            */
            Utilities.PrintLine();
            Console.WriteLine("Compute and relinearize x4th (x^4),");
            using Ciphertext x4th = new Ciphertext();
            evaluator.Square(xSquared, x4th);
            Console.WriteLine($"    + size of x4th: {x4th.Size}");
            evaluator.RelinearizeInplace(x4th, relinKeys);
            Console.WriteLine("    + size of x4th (after relinearization): {0}",
                x4th.Size);
            Console.WriteLine("    + noise budget in x4th: {0} bits",
                decryptor.InvariantNoiseBudget(x4th));
            decryptor.Decrypt(x4th, decryptedResult);
            batchEncoder.Decode(decryptedResult, podResult);
            Console.WriteLine("    + result plaintext matrix ...... Correct.");
            Utilities.PrintMatrix(podResult, (int)rowSize);

            /*
            Last we compute x^8. We run out of noise budget.
            */
            Utilities.PrintLine();
            Console.WriteLine("Compute and relinearize x8th (x^8),");
            using Ciphertext x8th = new Ciphertext();
            evaluator.Square(x4th, x8th);
            Console.WriteLine($"    + size of x8th: {x8th.Size}");
            evaluator.RelinearizeInplace(x8th, relinKeys);
            Console.WriteLine("    + size of x8th (after relinearization): {0}",
                x8th.Size);
            Console.WriteLine("    + noise budget in x8th: {0} bits",
                decryptor.InvariantNoiseBudget(x8th));
            Console.WriteLine("NOTE: Notice the increase in remaining noise budget.");

            Console.WriteLine();
            Console.WriteLine("~~~~~~ Use modulus switching to calculate x^8. ~~~~~~");

            /*
            Noise budget has reached 0, which means that decryption cannot be expected
            to give the correct result. BGV requires modulus switching to reduce noise
            growth. In the following demonstration, we will insert a modulus switching
            after each relinearization.
            */
            Utilities.PrintLine();
            Console.WriteLine("Encrypt xPlain to xEncrypted.");
            encryptor.Encrypt(xPlain, xEncrypted);
            Console.WriteLine("    + noise budget in freshly encrypted x: {0} bits",
                decryptor.InvariantNoiseBudget(xEncrypted));
            Console.WriteLine();

            /*
            Then we compute x^2.
            */
            Utilities.PrintLine();
            Console.WriteLine("Compute and relinearize xSquared (x^2),");
            Console.WriteLine("    + noise budget in xSquared (previously): {0} bits",
                decryptor.InvariantNoiseBudget(xSquared));
            evaluator.Square(xEncrypted, xSquared);
            evaluator.RelinearizeInplace(xSquared, relinKeys);
            evaluator.ModSwitchToNextInplace(xSquared);
            Console.WriteLine("    + noise budget in xSquared (with modulus switching): {0} bits",
                decryptor.InvariantNoiseBudget(xSquared));
            decryptor.Decrypt(xSquared, decryptedResult);
            batchEncoder.Decode(decryptedResult, podResult);
            Console.WriteLine("    + result plaintext matrix ...... Correct.");
            Utilities.PrintMatrix(podResult, (int)rowSize);

            /*
            Next we compute x^4.
            */
            Utilities.PrintLine();
            Console.WriteLine("Compute and relinearize x4th (x^4),");
            Console.WriteLine("    + noise budget in x4th (previously): {0} bits",
                decryptor.InvariantNoiseBudget(x4th));
            evaluator.Square(xSquared, x4th);
            evaluator.RelinearizeInplace(x4th, relinKeys);
            evaluator.ModSwitchToNextInplace(x4th);
            Console.WriteLine("    + noise budget in x4th (with modulus switching): {0} bits",
                decryptor.InvariantNoiseBudget(x4th));
            decryptor.Decrypt(x4th, decryptedResult);
            batchEncoder.Decode(decryptedResult, podResult);
            Console.WriteLine("    + result plaintext matrix ...... Correct.");
            Utilities.PrintMatrix(podResult, (int)rowSize);

            /*
            Last we compute x^8. We still have budget left.
            */
            Utilities.PrintLine();
            Console.WriteLine("Compute and relinearize x8th (x^8),");
            Console.WriteLine("    + noise budget in x8th (previously): {0} bits",
                decryptor.InvariantNoiseBudget(x8th));
            evaluator.Square(x4th, x8th);
            evaluator.RelinearizeInplace(x8th, relinKeys);
            evaluator.ModSwitchToNextInplace(x8th);
            Console.WriteLine("    + noise budget in x8th (with modulus switching): {0} bits",
                decryptor.InvariantNoiseBudget(x8th));
            decryptor.Decrypt(x8th, decryptedResult);
            batchEncoder.Decode(decryptedResult, podResult);
            Console.WriteLine("    + result plaintext matrix ...... Correct.");
            Utilities.PrintMatrix(podResult, (int)rowSize);

            /*
            Although with modulus switching x_squared has less noise budget than before,
            noise budget is consumed at a slower rate. To achieve the optimal consumption
            rate of noise budget in an application, one needs to carefully choose the
            location to insert modulus switching and manually choose coeff_modulus.
            */
        }
    }
}
