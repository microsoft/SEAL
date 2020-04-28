// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

using System;
using System.Collections.Generic;
using Microsoft.Research.SEAL;

namespace SEALNetExamples
{
    partial class Examples
    {
        private static void ExampleCKKSBasics()
        {
            Utilities.PrintExampleBanner("Example: CKKS Basics");

            /*
            In this example we demonstrate evaluating a polynomial function

                PI*x^3 + 0.4*x + 1

            on encrypted floating-point input data x for a set of 4096 equidistant points
            in the interval [0, 1]. This example demonstrates many of the main features
            of the CKKS scheme, but also the challenges in using it.

            We start by setting up the CKKS scheme.
            */
            using EncryptionParameters parms = new EncryptionParameters(SchemeType.CKKS);

            /*
            We saw in `2_Encoders.cs' that multiplication in CKKS causes scales in
            ciphertexts to grow. The scale of any ciphertext must not get too close to
            the total size of CoeffModulus, or else the ciphertext simply runs out of
            room to store the scaled-up plaintext. The CKKS scheme provides a `rescale'
            functionality that can reduce the scale, and stabilize the scale expansion.

            Rescaling is a kind of modulus switch operation (recall `3_Levels.cs').
            As modulus switching, it removes the last of the primes from CoeffModulus,
            but as a side-effect it scales down the ciphertext by the removed prime.
            Usually we want to have perfect control over how the scales are changed,
            which is why for the CKKS scheme it is more common to use carefully selected
            primes for the CoeffModulus.

            More precisely, suppose that the scale in a CKKS ciphertext is S, and the
            last prime in the current CoeffModulus (for the ciphertext) is P. Rescaling
            to the next level changes the scale to S/P, and removes the prime P from the
            CoeffModulus, as usual in modulus switching. The number of primes limits
            how many rescalings can be done, and thus limits the multiplicative depth of
            the computation.

            It is possible to choose the initial scale freely. One good strategy can be
            to is to set the initial scale S and primes P_i in the CoeffModulus to be
            very close to each other. If ciphertexts have scale S before multiplication,
            they have scale S^2 after multiplication, and S^2/P_i after rescaling. If all
            P_i are close to S, then S^2/P_i is close to S again. This way we stabilize the
            scales to be close to S throughout the computation. Generally, for a circuit
            of depth D, we need to rescale D times, i.e., we need to be able to remove D
            primes from the coefficient modulus. Once we have only one prime left in the
            coeff_modulus, the remaining prime must be larger than S by a few bits to
            preserve the pre-decimal-point value of the plaintext.

            Therefore, a generally good strategy is to choose parameters for the CKKS
            scheme as follows:

                (1) Choose a 60-bit prime as the first prime in CoeffModulus. This will
                    give the highest precision when decrypting;
                (2) Choose another 60-bit prime as the last element of CoeffModulus, as
                    this will be used as the special prime and should be as large as the
                    largest of the other primes;
                (3) Choose the intermediate primes to be close to each other.

            We use CoeffModulus.Create to generate primes of the appropriate size. Note
            that our CoeffModulus is 200 bits total, which is below the bound for our
            PolyModulusDegree: CoeffModulus.MaxBitCount(8192) returns 218.
            */
            ulong polyModulusDegree = 8192;
            parms.PolyModulusDegree = polyModulusDegree;
            parms.CoeffModulus = CoeffModulus.Create(
                polyModulusDegree, new int[]{ 60, 40, 40, 60 });

            /*
            We choose the initial scale to be 2^40. At the last level, this leaves us
            60-40=20 bits of precision before the decimal point, and enough (roughly
            10-20 bits) of precision after the decimal point. Since our intermediate
            primes are 40 bits (in fact, they are very close to 2^40), we can achieve
            scale stabilization as described above.
            */
            double scale = Math.Pow(2.0, 40);

            using SEALContext context = new SEALContext(parms);
            Utilities.PrintParameters(context);
            Console.WriteLine();

            using KeyGenerator keygen = new KeyGenerator(context);
            using PublicKey publicKey = keygen.PublicKey;
            using SecretKey secretKey = keygen.SecretKey;
            using RelinKeys relinKeys = keygen.RelinKeysLocal();
            using Encryptor encryptor = new Encryptor(context, publicKey);
            using Evaluator evaluator = new Evaluator(context);
            using Decryptor decryptor = new Decryptor(context, secretKey);

            using CKKSEncoder encoder = new CKKSEncoder(context);
            ulong slotCount = encoder.SlotCount;
            Console.WriteLine($"Number of slots: {slotCount}");

            List<double> input = new List<double>((int)slotCount);
            double currPoint = 0, stepSize = 1.0 / (slotCount - 1);
            for (ulong i = 0; i < slotCount; i++, currPoint += stepSize)
            {
                input.Add(currPoint);
            }
            Console.WriteLine("Input vector:");
            Utilities.PrintVector(input, 3, 7);

            Console.WriteLine("Evaluating polynomial PI*x^3 + 0.4x + 1 ...");

            /*
            We create plaintexts for PI, 0.4, and 1 using an overload of CKKSEncoder.Encode
            that encodes the given floating-point value to every slot in the vector.
            */
            using Plaintext plainCoeff3 = new Plaintext(),
                            plainCoeff1 = new Plaintext(),
                            plainCoeff0 = new Plaintext();
            encoder.Encode(3.14159265, scale, plainCoeff3);
            encoder.Encode(0.4, scale, plainCoeff1);
            encoder.Encode(1.0, scale, plainCoeff0);

            using Plaintext xPlain = new Plaintext();
            Utilities.PrintLine();
            Console.WriteLine("Encode input vectors.");
            encoder.Encode(input, scale, xPlain);
            using Ciphertext x1Encrypted = new Ciphertext();
            encryptor.Encrypt(xPlain, x1Encrypted);

            /*
            To compute x^3 we first compute x^2 and relinearize. However, the scale has
            now grown to 2^80.
            */
            using Ciphertext x3Encrypted = new Ciphertext();
            Utilities.PrintLine();
            Console.WriteLine("Compute x^2 and relinearize:");
            evaluator.Square(x1Encrypted, x3Encrypted);
            evaluator.RelinearizeInplace(x3Encrypted, relinKeys);
            Console.WriteLine("    + Scale of x^2 before rescale: {0} bits",
                Math.Log(x3Encrypted.Scale, newBase: 2));

            /*
            Now rescale; in addition to a modulus switch, the scale is reduced down by
            a factor equal to the prime that was switched away (40-bit prime). Hence, the
            new scale should be close to 2^40. Note, however, that the scale is not equal
            to 2^40: this is because the 40-bit prime is only close to 2^40.
            */
            Utilities.PrintLine();
            Console.WriteLine("Rescale x^2.");
            evaluator.RescaleToNextInplace(x3Encrypted);
            Console.WriteLine("    + Scale of x^2 after rescale: {0} bits",
                Math.Log(x3Encrypted.Scale, newBase: 2));

            /*
            Now x3Encrypted is at a different level than x1Encrypted, which prevents us
            from multiplying them to compute x^3. We could simply switch x1Encrypted to
            the next parameters in the modulus switching chain. However, since we still
            need to multiply the x^3 term with PI (plainCoeff3), we instead compute PI*x
            first and multiply that with x^2 to obtain PI*x^3. To this end, we compute
            PI*x and rescale it back from scale 2^80 to something close to 2^40.
            */
            Utilities.PrintLine();
            Console.WriteLine("Compute and rescale PI*x.");
            using Ciphertext x1EncryptedCoeff3 = new Ciphertext();
            evaluator.MultiplyPlain(x1Encrypted, plainCoeff3, x1EncryptedCoeff3);
            Console.WriteLine("    + Scale of PI*x before rescale: {0} bits",
                Math.Log(x1EncryptedCoeff3.Scale, newBase: 2));
            evaluator.RescaleToNextInplace(x1EncryptedCoeff3);
            Console.WriteLine("    + Scale of PI*x after rescale: {0} bits",
                Math.Log(x1EncryptedCoeff3.Scale, newBase: 2));

            /*
            Since x3Encrypted and x1EncryptedCoeff3 have the same exact scale and use
            the same encryption parameters, we can multiply them together. We write the
            result to x3Encrypted, relinearize, and rescale. Note that again the scale
            is something close to 2^40, but not exactly 2^40 due to yet another scaling
            by a prime. We are down to the last level in the modulus switching chain.
            */
            Utilities.PrintLine();
            Console.WriteLine("Compute, relinearize, and rescale (PI*x)*x^2.");
            evaluator.MultiplyInplace(x3Encrypted, x1EncryptedCoeff3);
            evaluator.RelinearizeInplace(x3Encrypted, relinKeys);
            Console.WriteLine("    + Scale of PI*x^3 before rescale: {0} bits",
                Math.Log(x3Encrypted.Scale, newBase: 2));
            evaluator.RescaleToNextInplace(x3Encrypted);
            Console.WriteLine("    + Scale of PI*x^3 after rescale: {0} bits",
                Math.Log(x3Encrypted.Scale, newBase: 2));

            /*
            Next we compute the degree one term. All this requires is one MultiplyPlain
            with plainCoeff1. We overwrite x1Encrypted with the result.
            */
            Utilities.PrintLine();
            Console.WriteLine("Compute and rescale 0.4*x.");
            evaluator.MultiplyPlainInplace(x1Encrypted, plainCoeff1);
            Console.WriteLine("    + Scale of 0.4*x before rescale: {0} bits",
                Math.Log(x1Encrypted.Scale, newBase: 2));
            evaluator.RescaleToNextInplace(x1Encrypted);
            Console.WriteLine("    + Scale of 0.4*x after rescale: {0} bits",
                Math.Log(x1Encrypted.Scale, newBase: 2));

            /*
            Now we would hope to compute the sum of all three terms. However, there is
            a serious problem: the encryption parameters used by all three terms are
            different due to modulus switching from rescaling.

            Encrypted addition and subtraction require that the scales of the inputs are
            the same, and also that the encryption parameters (ParmsId) match. If there
            is a mismatch, Evaluator will throw an exception.
            */
            Console.WriteLine();
            Utilities.PrintLine();
            Console.WriteLine("Parameters used by all three terms are different:");
            Console.WriteLine("    + Modulus chain index for x3Encrypted: {0}",
                context.GetContextData(x3Encrypted.ParmsId).ChainIndex);
            Console.WriteLine("    + Modulus chain index for x1Encrypted: {0}",
                context.GetContextData(x1Encrypted.ParmsId).ChainIndex);
            Console.WriteLine("    + Modulus chain index for plainCoeff0: {0}",
                context.GetContextData(plainCoeff0.ParmsId).ChainIndex);
            Console.WriteLine();

            /*
            Let us carefully consider what the scales are at this point. We denote the
            primes in coeff_modulus as P_0, P_1, P_2, P_3, in this order. P_3 is used as
            the special modulus and is not involved in rescalings. After the computations
            above the scales in ciphertexts are:

                - Product x^2 has scale 2^80 and is at level 2;
                - Product PI*x has scale 2^80 and is at level 2;
                - We rescaled both down to scale 2^80/P2 and level 1;
                - Product PI*x^3 has scale (2^80/P_2)^2;
                - We rescaled it down to scale (2^80/P_2)^2/P_1 and level 0;
                - Product 0.4*x has scale 2^80;
                - We rescaled it down to scale 2^80/P_2 and level 1;
                - The contant term 1 has scale 2^40 and is at level 2.

            Although the scales of all three terms are approximately 2^40, their exact
            values are different, hence they cannot be added together.
            */
            Utilities.PrintLine();
            Console.WriteLine("The exact scales of all three terms are different:");
            Console.WriteLine("    + Exact scale in PI*x^3: {0:0.0000000000}", x3Encrypted.Scale);
            Console.WriteLine("    + Exact scale in  0.4*x: {0:0.0000000000}", x1Encrypted.Scale);
            Console.WriteLine("    + Exact scale in      1: {0:0.0000000000}", plainCoeff0.Scale);
            Console.WriteLine();

            /*
            There are many ways to fix this problem. Since P_2 and P_1 are really close
            to 2^40, we can simply "lie" to Microsoft SEAL and set the scales to be the
            same. For example, changing the scale of PI*x^3 to 2^40 simply means that we
            scale the value of PI*x^3 by 2^120/(P_2^2*P_1), which is very close to 1.
            This should not result in any noticeable error.

            Another option would be to encode 1 with scale 2^80/P_2, do a MultiplyPlain
            with 0.4*x, and finally rescale. In this case we would need to additionally
            make sure to encode 1 with appropriate encryption parameters (ParmsId).

            In this example we will use the first (simplest) approach and simply change
            the scale of PI*x^3 and 0.4*x to 2^40.
            */
            Utilities.PrintLine();
            Console.WriteLine("Normalize scales to 2^40.");
            x3Encrypted.Scale = Math.Pow(2.0, 40);
            x1Encrypted.Scale = Math.Pow(2.0, 40);

            /*
            We still have a problem with mismatching encryption parameters. This is easy
            to fix by using traditional modulus switching (no rescaling). CKKS supports
            modulus switching just like the BFV scheme, allowing us to switch away parts
            of the coefficient modulus when it is simply not needed.
            */
            Utilities.PrintLine();
            Console.WriteLine("Normalize encryption parameters to the lowest level.");
            ParmsId lastParmsId = x3Encrypted.ParmsId;
            evaluator.ModSwitchToInplace(x1Encrypted, lastParmsId);
            evaluator.ModSwitchToInplace(plainCoeff0, lastParmsId);

            /*
            All three ciphertexts are now compatible and can be added.
            */
            Utilities.PrintLine();
            Console.WriteLine("Compute PI*x^3 + 0.4*x + 1.");
            using Ciphertext encryptedResult = new Ciphertext();
            evaluator.Add(x3Encrypted, x1Encrypted, encryptedResult);
            evaluator.AddPlainInplace(encryptedResult, plainCoeff0);

            /*
            First print the true result.
            */
            using Plaintext plainResult = new Plaintext();
            Utilities.PrintLine();
            Console.WriteLine("Decrypt and decode PI * x ^ 3 + 0.4x + 1.");
            Console.WriteLine("    + Expected result:");
            List<double> trueResult = new List<double>(input.Count);
            foreach (double x in input)
            {
                trueResult.Add((3.14159265 * x * x + 0.4) * x + 1);
            }
            Utilities.PrintVector(trueResult, 3, 7);

            /*
            We decrypt, decode, and print the result.
            */
            decryptor.Decrypt(encryptedResult, plainResult);
            List<double> result = new List<double>();
            encoder.Decode(plainResult, result);
            Console.WriteLine("    + Computed result ...... Correct.");
            Utilities.PrintVector(result, 3, 7);

            /*
            While we did not show any computations on complex numbers in these examples,
            the CKKSEncoder would allow us to have done that just as easily. Additions
            and multiplications of complex numbers behave just as one would expect.
            */
        }
    }
}
