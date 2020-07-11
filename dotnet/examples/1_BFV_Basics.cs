// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

using System;
using Microsoft.Research.SEAL;

namespace SEALNetExamples
{
    partial class Examples
    {
        private static void ExampleBFVBasics()
        {
            Utilities.PrintExampleBanner("Example: BFV Basics");

            /*
            In this example, we demonstrate performing simple computations (a polynomial
            evaluation) on encrypted integers using the BFV encryption scheme.

            The first task is to set up an instance of the EncryptionParameters class.
            It is critical to understand how the different parameters behave, how they
            affect the encryption scheme, performance, and the security level. There are
            three encryption parameters that are necessary to set:

                - PolyModulusDegree (degree of polynomial modulus);
                - CoeffModulus ([ciphertext] coefficient modulus);
                - PlainModulus (plaintext modulus; only for the BFV scheme).

            The BFV scheme cannot perform arbitrary computations on encrypted data.
            Instead, each ciphertext has a specific quantity called the `invariant noise
            budget' -- or `noise budget' for short -- measured in bits. The noise budget
            in a freshly encrypted ciphertext (initial noise budget) is determined by
            the encryption parameters. Homomorphic operations consume the noise budget
            at a rate also determined by the encryption parameters. In BFV the two basic
            operations allowed on encrypted data are additions and multiplications, of
            which additions can generally be thought of as being nearly free in terms of
            noise budget consumption compared to multiplications. Since noise budget
            consumption compounds in sequential multiplications, the most significant
            factor in choosing appropriate encryption parameters is the multiplicative
            depth of the arithmetic circuit that the user wants to evaluate on encrypted
            data. Once the noise budget of a ciphertext reaches zero it becomes too
            corrupted to be decrypted. Thus, it is essential to choose the parameters to
            be large enough to support the desired computation; otherwise the result is
            impossible to make sense of even with the secret key.
            */
            using EncryptionParameters parms = new EncryptionParameters(SchemeType.BFV);

            /*
            The first parameter we set is the degree of the `polynomial modulus'. This
            must be a positive power of 2, representing the degree of a power-of-two
            cyclotomic polynomial; it is not necessary to understand what this means.

            Larger PolyModulusDegree makes ciphertext sizes larger and all operations
            slower, but enables more complicated encrypted computations. Recommended
            values are 1024, 2048, 4096, 8192, 16384, 32768, but it is also possible
            to go beyond this range.

            In this example we use a relatively small polynomial modulus. Anything
            smaller than this will enable only very restricted encrypted computations.
            */
            ulong polyModulusDegree = 4096;
            parms.PolyModulusDegree = polyModulusDegree;

            /*
            Next we set the [ciphertext] `coefficient modulus' (CoeffModulus). This
            parameter is a large integer, which is a product of distinct prime numbers,
            numbers, each represented by an instance of the Modulus class. The
            bit-length of CoeffModulus means the sum of the bit-lengths of its prime
            factors.

            A larger CoeffModulus implies a larger noise budget, hence more encrypted
            computation capabilities. However, an upper bound for the total bit-length
            of the CoeffModulus is determined by the PolyModulusDegree, as follows:

                +----------------------------------------------------+
                | PolyModulusDegree   | max CoeffModulus bit-length  |
                +---------------------+------------------------------+
                | 1024                | 27                           |
                | 2048                | 54                           |
                | 4096                | 109                          |
                | 8192                | 218                          |
                | 16384               | 438                          |
                | 32768               | 881                          |
                +---------------------+------------------------------+

            These numbers can also be found in native/src/seal/util/hestdparms.h encoded
            in the function SEAL_HE_STD_PARMS_128_TC, and can also be obtained from the
            function

                CoeffModulus.MaxBitCount(polyModulusDegree).

            For example, if PolyModulusDegree is 4096, the coeff_modulus could consist
            of three 36-bit primes (108 bits).

            Microsoft SEAL comes with helper functions for selecting the CoeffModulus.
            For new users the easiest way is to simply use

                CoeffModulus.BFVDefault(polyModulusDegree),

            which returns IEnumerable<Modulus> consisting of a generally good choice
            for the given PolyModulusDegree.
            */
            parms.CoeffModulus = CoeffModulus.BFVDefault(polyModulusDegree);

            /*
            The plaintext modulus can be any positive integer, even though here we take
            it to be a power of two. In fact, in many cases one might instead want it
            to be a prime number; we will see this in later examples. The plaintext
            modulus determines the size of the plaintext data type and the consumption
            of noise budget in multiplications. Thus, it is essential to try to keep the
            plaintext data type as small as possible for best performance. The noise
            budget in a freshly encrypted ciphertext is

                ~ log2(CoeffModulus/PlainModulus) (bits)

            and the noise budget consumption in a homomorphic multiplication is of the
            form log2(PlainModulus) + (other terms).

            The plaintext modulus is specific to the BFV scheme, and cannot be set when
            using the CKKS scheme.
            */
            parms.PlainModulus = new Modulus(1024);

            /*
            Now that all parameters are set, we are ready to construct a SEALContext
            object. This is a heavy class that checks the validity and properties of the
            parameters we just set.

            C# 8.0 introduced the `using` declaration for local variables. This is a very
            convenient addition to the language: it causes the Dispose method for the
            object to be called at the end of the enclosing scope (in this case the end
            of this function), hence automatically releasing the native resources held by
            the object. This is helpful, because releasing the native resources returns
            the allocated memory to the memory pool, speeding up further allocations.
            Another way would be to call GC::Collect() at a convenient point in the code,
            but this may be less optimal as it may still cause unnecessary allocations
            of memory if native resources were not released early enough. In this program
            we call GC::Collect() after every example (see Examples.cs) to make sure
            everything is returned to the memory pool at latest before running the next
            example.
            */
            using SEALContext context = new SEALContext(parms);

            /*
            Print the parameters that we have chosen.
            */
            Utilities.PrintLine();
            Console.WriteLine("Set encryption parameters and print");
            Utilities.PrintParameters(context);

            /*
            When parameters are used to create SEALContext, Microsoft SEAL will first
            validate those parameters. The parameters chosen here are valid.
            */
            Console.WriteLine("Parameter validation (success): {0}", context.ParameterErrorMessage());

            Console.WriteLine();
            Console.WriteLine("~~~~~~ A naive way to calculate 4(x^2+1)(x+1)^2. ~~~~~~");

            /*
            The encryption schemes in Microsoft SEAL are public key encryption schemes.
            For users unfamiliar with this terminology, a public key encryption scheme
            has a separate public key for encrypting data, and a separate secret key for
            decrypting data. This way multiple parties can encrypt data using the same
            shared public key, but only the proper recipient of the data can decrypt it
            with the secret key.

            We are now ready to generate the secret and public keys. For this purpose
            we need an instance of the KeyGenerator class. Constructing a KeyGenerator
            automatically generates the public and secret key, which can immediately be
            read to local variables.
            */
            using KeyGenerator keygen = new KeyGenerator(context);
            using PublicKey publicKey = keygen.PublicKey;
            using SecretKey secretKey = keygen.SecretKey;

            /*
            To be able to encrypt we need to construct an instance of Encryptor. Note
            that the Encryptor only requires the public key, as expected.
            */
            using Encryptor encryptor = new Encryptor(context, publicKey);

            /*
            Computations on the ciphertexts are performed with the Evaluator class. In
            a real use-case the Evaluator would not be constructed by the same party
            that holds the secret key.
            */
            using Evaluator evaluator = new Evaluator(context);

            /*
            We will of course want to decrypt our results to verify that everything worked,
            so we need to also construct an instance of Decryptor. Note that the Decryptor
            requires the secret key.
            */
            using Decryptor decryptor = new Decryptor(context, secretKey);

            /*
            As an example, we evaluate the degree 4 polynomial

                4x^4 + 8x^3 + 8x^2 + 8x + 4

            over an encrypted x = 6. The coefficients of the polynomial can be considered
            as plaintext inputs, as we will see below. The computation is done modulo the
            plain_modulus 1024.

            While this examples is simple and easy to understand, it does not have much
            practical value. In later examples we will demonstrate how to compute more
            efficiently on encrypted integers and real or complex numbers.

            Plaintexts in the BFV scheme are polynomials of degree less than the degree
            of the polynomial modulus, and coefficients integers modulo the plaintext
            modulus. For readers with background in ring theory, the plaintext space is
            the polynomial quotient ring Z_T[X]/(X^N + 1), where N is PolyModulusDegree
            and T is PlainModulus.

            To get started, we create a plaintext containing the constant 6. For the
            plaintext element we use a constructor that takes the desired polynomial as
            a string with coefficients represented as hexadecimal numbers.
            */
            Utilities.PrintLine();
            int x = 6;
            using Plaintext xPlain = new Plaintext(x.ToString());
            Console.WriteLine($"Express x = {x} as a plaintext polynomial 0x{xPlain}.");

            /*
            We then encrypt the plaintext, producing a ciphertext.
            */
            Utilities.PrintLine();
            using Ciphertext xEncrypted = new Ciphertext();
            Console.WriteLine("Encrypt xPlain to xEncrypted.");
            encryptor.Encrypt(xPlain, xEncrypted);

            /*
            In Microsoft SEAL, a valid ciphertext consists of two or more polynomials
            whose coefficients are integers modulo the product of the primes in the
            coeff_modulus. The number of polynomials in a ciphertext is called its `size'
            and is given by Ciphertext.Size. A freshly encrypted ciphertext always has
            size 2.
            */
            Console.WriteLine($"    + size of freshly encrypted x: {xEncrypted.Size}");

            /*
            There is plenty of noise budget left in this freshly encrypted ciphertext.
            */
            Console.WriteLine("    + noise budget in freshly encrypted x: {0} bits",
                decryptor.InvariantNoiseBudget(xEncrypted));

            /*
            We decrypt the ciphertext and print the resulting plaintext in order to
            demonstrate correctness of the encryption.
            */
            using Plaintext xDecrypted = new Plaintext();
            Console.Write("    + decryption of encrypted_x: ");
            decryptor.Decrypt(xEncrypted, xDecrypted);
            Console.WriteLine($"0x{xDecrypted} ...... Correct.");

            /*
            When using Microsoft SEAL, it is typically advantageous to compute in a way
            that minimizes the longest chain of sequential multiplications. In other
            words, encrypted computations are best evaluated in a way that minimizes
            the multiplicative depth of the computation, because the total noise budget
            consumption is proportional to the multiplicative depth. For example, for
            our example computation it is advantageous to factorize the polynomial as

                4x^4 + 8x^3 + 8x^2 + 8x + 4 = 4(x + 1)^2 * (x^2 + 1)

            to obtain a simple depth 2 representation. Thus, we compute (x + 1)^2 and
            (x^2 + 1) separately, before multiplying them, and multiplying by 4.

            First, we compute x^2 and add a plaintext "1". We can clearly see from the
            print-out that multiplication has consumed a lot of noise budget. The user
            can vary the plain_modulus parameter to see its effect on the rate of noise
            budget consumption.
            */
            Utilities.PrintLine();
            Console.WriteLine("Compute xSqPlusOne (x^2+1).");
            using Ciphertext xSqPlusOne = new Ciphertext();
            evaluator.Square(xEncrypted, xSqPlusOne);
            using Plaintext plainOne = new Plaintext("1");
            evaluator.AddPlainInplace(xSqPlusOne, plainOne);

            /*
            Encrypted multiplication results in the output ciphertext growing in size.
            More precisely, if the input ciphertexts have size M and N, then the output
            ciphertext after homomorphic multiplication will have size M+N-1. In this
            case we perform a squaring, and observe both size growth and noise budget
            consumption.
            */
            Console.WriteLine($"    + size of xSqPlusOne: {xSqPlusOne.Size}");
            Console.WriteLine("    + noise budget in xSqPlusOne: {0} bits",
                decryptor.InvariantNoiseBudget(xSqPlusOne));

            /*
            Even though the size has grown, decryption works as usual as long as noise
            budget has not reached 0.
            */
            using Plaintext decryptedResult = new Plaintext();
            Console.Write("    + decryption of xSqPlusOne: ");
            decryptor.Decrypt(xSqPlusOne, decryptedResult);
            Console.WriteLine($"0x{decryptedResult} ...... Correct.");

            /*
            Next, we compute (x + 1)^2.
            */
            Utilities.PrintLine();
            Console.WriteLine("Compute xPlusOneSq ((x+1)^2).");
            using Ciphertext xPlusOneSq = new Ciphertext();
            evaluator.AddPlain(xEncrypted, plainOne, xPlusOneSq);
            evaluator.SquareInplace(xPlusOneSq);
            Console.WriteLine($"    + size of xPlusOneSq: {xPlusOneSq.Size}");
            Console.WriteLine("    + noise budget in xPlusOneSq: {0} bits",
                decryptor.InvariantNoiseBudget(xPlusOneSq));
            Console.Write("    + decryption of xPlusOneSq: ");
            decryptor.Decrypt(xPlusOneSq, decryptedResult);
            Console.WriteLine($"0x{decryptedResult} ...... Correct.");

            /*
            Finally, we multiply (x^2 + 1) * (x + 1)^2 * 4.
            */
            Utilities.PrintLine();
            Console.WriteLine("Compute encryptedResult (4(x^2+1)(x+1)^2).");
            using Ciphertext encryptedResult = new Ciphertext();
            using Plaintext plainFour = new Plaintext("4");
            evaluator.MultiplyPlainInplace(xSqPlusOne, plainFour);
            evaluator.Multiply(xSqPlusOne, xPlusOneSq, encryptedResult);
            Console.WriteLine($"    + size of encrypted_result: {encryptedResult.Size}");
            Console.WriteLine("    + noise budget in encrypted_result: {0} bits",
                decryptor.InvariantNoiseBudget(encryptedResult));
            Console.WriteLine("NOTE: Decryption can be incorrect if noise budget is zero.");

            Console.WriteLine();
            Console.WriteLine("~~~~~~ A better way to calculate 4(x^2+1)(x+1)^2. ~~~~~~");

            /*
            Noise budget has reached 0, which means that decryption cannot be expected
            to give the correct result. This is because both ciphertexts xSqPlusOne and
            xPlusOneSq consist of 3 polynomials due to the previous squaring operations,
            and homomorphic operations on large ciphertexts consume much more noise budget
            than computations on small ciphertexts. Computing on smaller ciphertexts is
            also computationally significantly cheaper.

            `Relinearization' is an operation that reduces the size of a ciphertext after
            multiplication back to the initial size, 2. Thus, relinearizing one or both
            input ciphertexts before the next multiplication can have a huge positive
            impact on both noise growth and performance, even though relinearization has
            a significant computational cost itself. It is only possible to relinearize
            size 3 ciphertexts down to size 2, so often the user would want to relinearize
            after each multiplication to keep the ciphertext sizes at 2.

            Relinearization requires special `relinearization keys', which can be thought
            of as a kind of public key. Relinearization keys can easily be created with
            the KeyGenerator.

            Relinearization is used similarly in both the BFV and the CKKS schemes, but
            in this example we continue using BFV. We repeat our computation from before,
            but this time relinearize after every multiplication.

            Here we use the function KeyGenerator.RelinKeysLocal(). In production code
            it is much better to use KeyGenerator.RelinKeys() instead. We will explain
            and discuss these differences in `6_Serialization.cs'.
            */
            Utilities.PrintLine();
            Console.WriteLine("Generate locally usable relinearization keys.");
            using RelinKeys relinKeys = keygen.RelinKeysLocal();

            /*
            We now repeat the computation relinearizing after each multiplication.
            */
            Utilities.PrintLine();
            Console.WriteLine("Compute and relinearize xSquared (x^2),");
            Console.WriteLine(new string(' ', 13) + "then compute xSqPlusOne (x^2+1)");
            using Ciphertext xSquared = new Ciphertext();
            evaluator.Square(xEncrypted, xSquared);
            Console.WriteLine($"    + size of xSquared: {xSquared.Size}");
            evaluator.RelinearizeInplace(xSquared, relinKeys);
            Console.WriteLine("    + size of xSquared (after relinearization): {0}",
                xSquared.Size);
            evaluator.AddPlain(xSquared, plainOne, xSqPlusOne);
            Console.WriteLine("    + noise budget in xSqPlusOne: {0} bits",
                decryptor.InvariantNoiseBudget(xSqPlusOne));
            Console.Write("    + decryption of xSqPlusOne: ");
            decryptor.Decrypt(xSqPlusOne, decryptedResult);
            Console.WriteLine($"0x{decryptedResult} ...... Correct.");

            Utilities.PrintLine();
            using Ciphertext xPlusOne = new Ciphertext();
            Console.WriteLine("Compute xPlusOne (x+1),");
            Console.WriteLine(new string(' ', 13) +
                "then compute and relinearize xPlusOneSq ((x+1)^2).");
            evaluator.AddPlain(xEncrypted, plainOne, xPlusOne);
            evaluator.Square(xPlusOne, xPlusOneSq);
            Console.WriteLine($"    + size of xPlusOneSq: {xPlusOneSq.Size}");
            evaluator.RelinearizeInplace(xPlusOneSq, relinKeys);
            Console.WriteLine("    + noise budget in xPlusOneSq: {0} bits",
                decryptor.InvariantNoiseBudget(xPlusOneSq));
            Console.Write("    + decryption of xPlusOneSq: ");
            decryptor.Decrypt(xPlusOneSq, decryptedResult);
            Console.WriteLine($"0x{decryptedResult} ...... Correct.");

            Utilities.PrintLine();
            Console.WriteLine("Compute and relinearize encryptedResult (4(x^2+1)(x+1)^2).");
            evaluator.MultiplyPlainInplace(xSqPlusOne, plainFour);
            evaluator.Multiply(xSqPlusOne, xPlusOneSq, encryptedResult);
            Console.WriteLine($"    + size of encryptedResult: {encryptedResult.Size}");
            evaluator.RelinearizeInplace(encryptedResult, relinKeys);
            Console.WriteLine("    + size of encryptedResult (after relinearization): {0}",
                encryptedResult.Size);
            Console.WriteLine("    + noise budget in encryptedResult: {0} bits",
                decryptor.InvariantNoiseBudget(encryptedResult));

            Console.WriteLine();
            Console.WriteLine("NOTE: Notice the increase in remaining noise budget.");

            /*
            Relinearization clearly improved our noise consumption. We have still plenty
            of noise budget left, so we can expect the correct answer when decrypting.
            */
            Utilities.PrintLine();
            Console.WriteLine("Decrypt encrypted_result (4(x^2+1)(x+1)^2).");
            decryptor.Decrypt(encryptedResult, decryptedResult);
            Console.WriteLine("    + decryption of 4(x^2+1)(x+1)^2 = 0x{0} ...... Correct.",
                decryptedResult);

            /*
            For x=6, 4(x^2+1)(x+1)^2 = 7252. Since the plaintext modulus is set to 1024,
            this result is computed in integers modulo 1024. Therefore the expected output
            should be 7252 % 1024 == 84, or 0x54 in hexadecimal.
            */

            /*
            Sometimes we create customized encryption parameters which turn out to be invalid.
            Microsoft SEAL can interpret the reason why parameters are considered invalid.
            Here we simply reduce the polynomial modulus degree to make the parameters not
            compliant with the HomomorphicEncryption.org security standard.
            */
            Utilities.PrintLine();
            Console.WriteLine("An example of invalid parameters");
            parms.PolyModulusDegree = 2048;
            using SEALContext new_context = new SEALContext(parms);
            Utilities.PrintParameters(context);
            Console.WriteLine("Parameter validation (failed): {0}", new_context.ParameterErrorMessage());
            Console.WriteLine();

            /*
            This information is helpful to fix invalid encryption parameters.
            */
        }
    }
}
