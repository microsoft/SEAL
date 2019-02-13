// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

using Microsoft.Research.SEAL;
using System;
using System.Linq;
using System.Collections.Generic;
using System.Diagnostics;

namespace SEALNetExamples
{
    class Examples
    {
        private static void ExampleBFVBasicsI()
        {
            Utilities.PrintExampleBanner("Example: BFV Basics I");

            /*
            In this example we demonstrate setting up encryption parameters and other 
            relevant objects for performing simple computations on encrypted integers.

            Microsoft SEAL implements two encryption schemes: the Brakerski/Fan-Vercauteren (BFV) 
            scheme and the Cheon-Kim-Kim-Song (CKKS) scheme. In the first examples we 
            use the BFV scheme as it is far easier to understand and use than CKKS. For 
            more details on the basics of the BFV scheme, we refer the reader to the
            original paper https://eprint.iacr.org/2012/144. In truth, to achieve good 
            performance Microsoft SEAL implements the "FullRNS" optimization as described in 
            https://eprint.iacr.org/2016/510, but this optimization is invisible to 
            the user and has no security implications. We will discuss the CKKS scheme
            in later examples.

            The first task is to set up an instance of the EncryptionParameters class.
            It is critical to understand how these different parameters behave, how they
            affect the encryption scheme, performance, and the security level. There are 
            three encryption parameters that are necessary to set: 

                - PolyModulusDegree (degree of polynomial modulus);
                - CoeffModulus ([ciphertext] coefficient modulus);
                - PlainModulus (plaintext modulus).

            A fourth parameter -- NoiseStandardDeviation -- has a default value 3.20 
            and should not be necessary to modify unless the user has a specific reason 
            to do so and has an in-depth understanding of the security implications.

            A fifth parameter -- RandomGenerator -- can be set to use customized random
            number generators. By default, Microsoft SEAL uses hardware-based AES in counter mode
            for pseudo-randomness with key generated using std::random_device. If the 
            AES-NI instruction set is not available, all randomness is generated from 
            std::random_device. Most academic users in particular should have little 
            reason to change this.

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
            EncryptionParameters parms = new EncryptionParameters(SchemeType.BFV);

            /*
            The first parameter we set is the degree of the polynomial modulus. This must
            be a positive power of 2, representing the degree of a power-of-2 cyclotomic 
            polynomial; it is not necessary to understand what this means. The polynomial 
            modulus degree should be thought of mainly affecting the security level of the 
            scheme: larger degree makes the scheme more secure. Larger degree also makes 
            ciphertext sizes larger, and consequently all operations slower. Recommended 
            degrees are 1024, 2048, 4096, 8192, 16384, 32768, but it is also possible to 
            go beyond this. In this example we use a relatively small polynomial modulus.
            */
            parms.PolyModulusDegree = 2048;

            /*
            Next we set the [ciphertext] coefficient modulus (CoeffModulus). The size 
            of the coefficient modulus should be thought of as the most significant 
            factor in determining the noise budget in a freshly encrypted ciphertext: 
            bigger means more noise budget, which is desirable. On the other hand, 
            a larger coefficient modulus lowers the security level of the scheme. Thus, 
            if a large noise budget is required for complicated computations, a large 
            coefficient modulus needs to be used, and the reduction in the security 
            level must be countered by simultaneously increasing the polynomial modulus. 
            Overall, this will result in worse performance.

            To make parameter selection easier for the user, we have constructed sets 
            of largest safe coefficient moduli for 128-bit and 192-bit security levels
            for different choices of the polynomial modulus. These default parameters 
            follow the recommendations in the Security Standard Draft available at 
            http://HomomorphicEncryption.org. The security estimates are a complicated
            topic and we highly recommend consulting with experts in the field when 
            selecting parameters. 

            Our recommended values for the coefficient modulus can be easily accessed 
            through the functions 

                DefaultParams.CoeffModulus128(int)
                DefaultParams.CoeffModulus192(int)
                DefaultParams.CoeffModulus256(int)

            for 128-bit, 192-bit, and 256-bit security levels. The integer parameter is 
            the degree of the polynomial modulus used.

            In Microsoft SEAL the coefficient modulus is a positive composite number -- a product
            of distinct primes of size up to 60 bits. When we talk about the size of the 
            coefficient modulus we mean the bit length of the product of the primes. The 
            small primes are represented by instances of the SmallModulus class so for
            example DefaultParams.CoeffModulus128(int) returns an enumeration of SmallModulus
            instances. 

            It is possible for the user to select their own small primes. Since Microsoft SEAL uses
            the Number Theoretic Transform (NTT) for polynomial multiplications modulo the
            factors of the coefficient modulus, the factors need to be prime numbers
            congruent to 1 modulo 2*PolyModulusDegree. We have generated a list of such
            prime numbers of various sizes that the user can easily access through the
            functions 

                DefaultParams.SmallMods60bit(int)
                DefaultParams.SmallMods50bit(int)
                DefaultParams.SmallMods40bit(int)
                DefaultParams.SmallMods30bit(int)

            each of which gives access to an array of primes of the denoted size. These 
            primes are located in the source file util/globals.cpp. Again, please keep 
            in mind that the choice of CoeffModulus has a dramatic effect on security 
            and should almost always be obtained through CoeffModulusXXX(int).

            Performance is mainly affected by the size of the polynomial modulus, and 
            the number of prime factors in the coefficient modulus; hence in some cases
            it can be important to use as few prime factors in the coefficient modulus 
            as possible.

            In this example we use the default coefficient modulus for a 128-bit security
            level. Concretely, this coefficient modulus consists of only one 54-bit prime 
            factor: 0x3fffffff000001.
            */
            parms.CoeffModulus = DefaultParams.CoeffModulus128(polyModulusDegree: 2048);

            /*
            The plaintext modulus can be any positive integer, even though here we take 
            it to be a power of two. In fact, in many cases one might instead want it 
            to be a prime number; we will see this in later examples. The plaintext 
            modulus determines the size of the plaintext data type but it also affects 
            the noise budget in a freshly encrypted ciphertext and the consumption of
            noise budget in homomorphic (encrypted) multiplications. Thus, it is 
            essential to try to keep the plaintext data type as small as possible for 
            best performance. The noise budget in a freshly encrypted ciphertext is 

                ~ log2(CoeffModulus/PlainModulus) (bits)

            and the noise budget consumption in a homomorphic multiplication is of the 
            form log2(PlainModulus) + (other terms).
            */
            parms.PlainModulus = new SmallModulus(1 << 8);

            /*
            Now that all parameters are set, we are ready to construct a SEALContext 
            object. This is a heavy class that checks the validity and properties of the 
            parameters we just set and performs several important pre-computations.
            */
            SEALContext context = SEALContext.Create(parms);

            /*
            Print the parameters that we have chosen.
            */
            Utilities.PrintParameters(context);

            /*
            Plaintexts in the BFV scheme are polynomials with coefficients integers 
            modulo PlainModulus. This is not a very practical object to encrypt: much
            more useful would be encrypting integers or floating point numbers. For this
            we need an `encoding scheme' to convert data from integer representation to
            an appropriate plaintext polynomial representation than can subsequently be 
            encrypted. Microsoft SEAL comes with a few basic encoders for the BFV scheme:

            [IntegerEncoder]
            The IntegerEncoder encodes integers to plaintext polynomials as follows. 
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
            integers modulo PlainModulus, implicit reduction modulo PlainModulus may 
            yield unexpected results. For example, adding 1x^4 + 1x^3 + 1x^1 to itself 
            PlainModulus many times will result in the constant polynomial 0, which is 
            clearly not equal to 26 * PlainModulus. It can be difficult to predict when 
            such overflow will take place especially when computing several sequential
            multiplications. BatchEncoder (discussed later) makes it easier to predict 
            encoding overflow conditions but has a stronger restriction on the size of 
            the numbers it can encode. 

            The IntegerEncoder is easy to understand and use for simple computations, 
            and can be a good starting point to learning Microsoft SEAL. However, advanced users 
            will probably prefer more efficient approaches, such as the BatchEncoder or 
            the CKKSEncoder (discussed later).

            [BatchEncoder]
            If PlainModulus is a prime congruent to 1 modulo 2*PolyModulusDegree, the 
            plaintext elements can be viewed as 2-by-(PolyModulusDegree / 2) matrices
            with elements integers modulo PlainModulus. When a desired computation can 
            be vectorized, using BatchEncoder can result in a massive performance boost
            over naively encrypting and operating on each input number separately. Thus, 
            in more complicated computations this is likely to be by far the most 
            important and useful encoder. In ExampleBFVBasicsIII() we show how to
            operate on encrypted matrix plaintexts.

            In this example we use the IntegerEncoder due to its simplicity. 
            */
            IntegerEncoder encoder = new IntegerEncoder(context);

            /*
            We are now ready to generate the secret and public keys. For this purpose 
            we need an instance of the KeyGenerator class. Constructing a KeyGenerator 
            automatically generates the public and secret key, which can then be read to 
            local variables.
            */
            KeyGenerator keygen = new KeyGenerator(context);
            PublicKey publicKey = keygen.PublicKey;
            SecretKey secretKey = keygen.SecretKey;

            /*
            To be able to encrypt we need to construct an instance of Encryptor. Note 
            that the Encryptor only requires the public key, as expected.
            */
            Encryptor encryptor = new Encryptor(context, publicKey);

            /*
            Computations on the ciphertexts are performed with the Evaluator class. In
            a real use-case the Evaluator would not be constructed by the same party 
            that holds the secret key.
            */
            Evaluator evaluator = new Evaluator(context);

            /*
            We will of course want to decrypt our results to verify that everything worked,
            so we need to also construct an instance of Decryptor. Note that the Decryptor
            requires the secret key.
            */
            Decryptor decryptor = new Decryptor(context, secretKey);

            /*
            We start by encoding two integers as plaintext polynomials.
            */
            int value1 = 5;
            Plaintext plain1 = encoder.Encode(value1);
            Console.WriteLine($"Encoded {value1} as polynomial {plain1.ToString()} (plain1)");

            int value2 = -7;
            Plaintext plain2 = encoder.Encode(value2);
            Console.WriteLine($"Encoded {value2} as polynomial {plain2.ToString()} (plain2)");

            /*
            Encrypting the encoded values is easy.
            */
            Ciphertext encrypted1 = new Ciphertext();
            Ciphertext encrypted2 = new Ciphertext();
            Console.Write("Encrypting plain1: ");
            encryptor.Encrypt(plain1, encrypted1);
            Console.WriteLine("Done (encrypted1)");

            Console.Write("Encrypting plain2: ");
            encryptor.Encrypt(plain2, encrypted2);
            Console.WriteLine("Done (encrypted2)");

            /*
            To illustrate the concept of noise budget, we print the budgets in the fresh 
            encryptions.
            */
            Console.WriteLine($"Noise budget in encrypted1: {decryptor.InvariantNoiseBudget(encrypted1)} bits");
            Console.WriteLine($"Noise budget in encrypted2: {decryptor.InvariantNoiseBudget(encrypted2)} bits");

            /*
            As a simple example, we compute (-encrypted1 + encrypted2) * encrypted2. Most 
            basic arithmetic operations come as in-place two-argument versions that
            overwrite the first argument with the result, and as three-argument versions
            taking as separate destination parameter. In most cases the in-place variants
            are slightly faster.
            */

            /*
            Negation is a unary operation and does not consume any noise budget.
            */
            evaluator.NegateInplace(encrypted1);
            Console.WriteLine($"Noise budget in -encrypted1: {decryptor.InvariantNoiseBudget(encrypted1)} bits");

            /*
            Compute the sum of encrypted1 and encrypted2; the sum overwrites encrypted1.
            */
            evaluator.AddInplace(encrypted1, encrypted2);

            /*
            Addition sets the noise budget to the minimum of the input noise budgets. 
            In this case both inputs had roughly the same budget going in, so the output 
            (in encrypted1) has just a slightly lower budget. Depending on probabilistic 
            effects the noise growth consumption may or may not be visible when measured 
            in whole bits.
            */
            Console.WriteLine($"Noise budget in -encrypted1 + encrypted2: {decryptor.InvariantNoiseBudget(encrypted1)} bits");

            /*
            Finally multiply with encrypted2. Again, we use the in-place version of the
            function, overwriting encrypted1 with the product.
            */
            evaluator.MultiplyInplace(encrypted1, encrypted2);

            /*
            Multiplication consumes a lot of noise budget. This is clearly seen in the
            print-out. The user can change the PlainModulus to see its effect on the
            rate of noise budget consumption.
            */
            Console.WriteLine($"Noise budget in (-encrypted1 + encrypted2) * encrypted2: {decryptor.InvariantNoiseBudget(encrypted1)} bits");

            /*
            Now we decrypt and decode our result.
            */
            Plaintext plainResult = new Plaintext();
            Console.Write("Decrypting result: ");
            decryptor.Decrypt(encrypted1, plainResult);
            Console.WriteLine("Done");

            /*
            Print the result plaintext polynomial.
            */
            Console.WriteLine($"Plaintext polynomial: {plainResult.ToString()}");

            /*
            Decode to obtain an integer result.
            */
            Console.WriteLine($"Decoded integer: {encoder.DecodeInt32(plainResult)}");
        }

        private static void ExampleBFVBasicsII()
        {
            Utilities.PrintExampleBanner("Example: BFV Basics II");

            /*
            In this example we explain what relinearization is, how to use it, and how 
            it affects noise budget consumption. Relinearization is used both in the BFV
            and the CKKS schemes but in this example (for the sake of simplicity) we 
            again focus on BFV.

            First we set the parameters, create a SEALContext, and generate the public
            and secret keys. We use slightly larger parameters than before to be able to 
            do more homomorphic multiplications.
            */
            EncryptionParameters parms = new EncryptionParameters(SchemeType.BFV);
            parms.PolyModulusDegree = 8192;

            /*
            The default coefficient modulus consists of the following primes:

                0x7fffffff380001,  0x7ffffffef00001,
                0x3fffffff000001,  0x3ffffffef40001

            The total size is 218 bits.
            */
            parms.CoeffModulus = DefaultParams.CoeffModulus128(polyModulusDegree: 8192);
            parms.SetPlainModulus(1 << 10);

            SEALContext context = SEALContext.Create(parms);
            Utilities.PrintParameters(context);

            /*
            We generate the public and secret keys as before. 

            There are actually two more types of keys in Microsoft SEAL: `relinearization keys' 
            and `Galois keys'. In this example we will discuss relinearization keys, and 
            Galois keys will be discussed later in ExampleBFVBasicsIII().
            */
            KeyGenerator keygen = new KeyGenerator(context);
            PublicKey publicKey = keygen.PublicKey;
            SecretKey secretKey = keygen.SecretKey;

            /*
            We also set up an Encryptor, Evaluator, and Decryptor here. We will
            encrypt polynomials directly in this example, so there is no need for
            an encoder.
            */
            Encryptor encryptor = new Encryptor(context, publicKey);
            Evaluator evaluator = new Evaluator(context);
            Decryptor decryptor = new Decryptor(context, secretKey);

            /*
            We can easily construct a plaintext polynomial from a string. Again, note 
            how there is no need for encoding since the BFV scheme natively encrypts
            polynomials.
            */
            Plaintext plain1 = new Plaintext("1x^2 + 2x^1 + 3");
            Ciphertext encrypted = new Ciphertext();
            Console.Write($"Encrypting {plain1.ToString()}: ");
            encryptor.Encrypt(plain1, encrypted);
            Console.WriteLine("Done");

            /*
            In Microsoft SEAL, a valid ciphertext consists of two or more polynomials whose 
            coefficients are integers modulo the product of the primes in CoeffModulus. 
            The current size of a ciphertext can be found using Ciphertext.Size.
            A freshly encrypted ciphertext always has size 2.
            */
            Console.WriteLine($"Size of a fresh encryption: {encrypted.Size}");
            Console.WriteLine($"Noise budget in fresh encryption: {decryptor.InvariantNoiseBudget(encrypted)} bits");

            /*
            Homomorphic multiplication results in the output ciphertext growing in size. 
            More precisely, if the input ciphertexts have size M and N, then the output 
            ciphertext after homomorphic multiplication will have size M+N-1. In this
            case we square encrypted twice to observe this growth (also observe noise
            budget consumption).
            */
            evaluator.SquareInplace(encrypted);
            Console.WriteLine($"Size after squaring: {encrypted.Size}");
            Console.WriteLine($"Noise budget after squaring: {decryptor.InvariantNoiseBudget(encrypted)} bits");

            evaluator.SquareInplace(encrypted);
            Console.WriteLine($"Size after second squaring: {encrypted.Size}");
            Console.WriteLine($"Noise budget after second squaring: {decryptor.InvariantNoiseBudget(encrypted)} bits");

            /*
            It does not matter that the size has grown -- decryption works as usual.
            Observe from the print-out that the coefficients in the plaintext have grown 
            quite large. One more squaring would cause some of them to wrap around the
            PlainModulus (0x400) and as a result we would no longer obtain the expected 
            result as an integer-coefficient polynomial. We can fix this problem to some 
            extent by increasing PlainModulus. This makes sense since we still have 
            plenty of noise budget left.
            */
            Plaintext plain2 = new Plaintext();
            decryptor.Decrypt(encrypted, plain2);
            Console.WriteLine($"Fourth power: {plain2.ToString()}");
            Console.WriteLine();

            /*
            The problem here is that homomorphic operations on large ciphertexts are
            computationally much more costly than on small ciphertexts. Specifically,
            homomorphic multiplication on input ciphertexts of size M and N will require 
            O(M*N) polynomial multiplications to be performed, and an addition will
            require O(M+N) additions. Relinearization reduces the size of ciphertexts
            after multiplication back to the initial size (2). Thus, relinearizing one
            or both inputs before the next multiplication or e.g. before serializing the
            ciphertexts, can have a huge positive impact on performance.

            Another problem is that the noise budget consumption in multiplication is
            bigger when the input ciphertexts sizes are bigger. In a complicated
            computation the contribution of the sizes to the noise budget consumption
            can actually become the dominant term. We will point this out again below
            once we get to our example.

            Relinearization itself has both a computational cost and a noise budget cost.
            These both depend on a parameter called `decomposition bit count', which can
            be any integer at least 1 [DefaultParams.DBCmin] and at most 60
            [DefaultParams.DBCmax]. A large decomposition bit count makes relinearization
            fast, but consumes more noise budget. A small decomposition bit count can
            make relinearization slower, but  might not change the noise budget by any
            observable amount.

            Relinearization requires a special type of key called `relinearization keys'.
            These can be created by the KeyGenerator for any decomposition bit count.
            To relinearize a ciphertext of size M >= 2 back to size 2, we actually need 
            M-2 relinearization keys. Attempting to relinearize a too large ciphertext 
            with too few relinearization keys will result in an exception being thrown.

            We repeat our computation, but this time relinearize after both squarings.
            Since our ciphertext never grows past size 3 (we relinearize after every
            multiplication), it suffices to generate only one relinearization key. This
            (relinearizing after every multiplication) should be the preferred approach 
            in almost all cases.

            First, we need to create relinearization keys. We use a decomposition bit 
            count of 16 here, which should be thought of as very small.

            This function generates one single relinearization key. Another overload 
            of KeyGenerator::relin_keys takes the number of keys to be generated as an 
            argument, but one is all we need in this example (see above).
            */
            RelinKeys relinKeys16 = keygen.RelinKeys(decompositionBitCount: 16);

            Console.Write($"Encrypting {plain1.ToString()}: ");
            encryptor.Encrypt(plain1, encrypted);
            Console.WriteLine("Done");
            Console.WriteLine($"Size of a fresh encryption: {encrypted.Size}");
            Console.WriteLine($"Noise budget in fresh encryption: {decryptor.InvariantNoiseBudget(encrypted)} bits");

            evaluator.SquareInplace(encrypted);
            Console.WriteLine($"Size after squaring: {encrypted.Size}");
            Console.WriteLine($"Noise budget after squaring: {decryptor.InvariantNoiseBudget(encrypted)} bits");

            evaluator.RelinearizeInplace(encrypted, relinKeys16);
            Console.WriteLine($"Size after relinearization: {encrypted.Size}");
            Console.WriteLine($"Noise budget after relinearizing (dbc = {relinKeys16.DecompositionBitCount}): {decryptor.InvariantNoiseBudget(encrypted)} bits");

            evaluator.SquareInplace(encrypted);
            Console.WriteLine($"Size after second squaring: {encrypted.Size}");
            Console.WriteLine($"Noise budget after second squaring: {decryptor.InvariantNoiseBudget(encrypted)} bits");

            evaluator.RelinearizeInplace(encrypted, relinKeys16);
            Console.WriteLine($"Size after relinearization: {encrypted.Size}");
            Console.WriteLine($"Noise budget after relinearizing (dbc = {relinKeys16.DecompositionBitCount}): {decryptor.InvariantNoiseBudget(encrypted)} bits");

            decryptor.Decrypt(encrypted, plain2);
            Console.WriteLine($"Fourth power: {plain2.ToString()}");
            Console.WriteLine();

            /*
            Of course the result is still the same, but this time we actually used less 
            of our noise budget. This is not surprising for two reasons:

                - We used a very small decomposition bit count, which is why
                  relinearization itself did not consume the noise budget by any
                  observable amount;
                - Since our ciphertext sizes remain small throughout the two
                  squarings, the noise budget consumption rate in multiplication
                  remains as small as possible. Recall from above that operations
                  on larger ciphertexts actually cause more noise growth.

            To make things more clear, we repeat the computation a third time, now using 
            the largest possible decomposition bit count (60). We are not measuring
            running time here, but relinearization with relinKeys60 (below) is much 
            faster than with relinKeys16.
            */
            RelinKeys relinKeys60 = keygen.RelinKeys(decompositionBitCount: DefaultParams.DBCmax);

            Console.Write($"Encrypting: {plain1.ToString()}: ");
            encryptor.Encrypt(plain1, encrypted);
            Console.WriteLine("Done");
            Console.WriteLine($"Size of a fresh encryption: {encrypted.Size}");
            Console.WriteLine($"Noise budget in fresh encryption: {decryptor.InvariantNoiseBudget(encrypted)} bits");

            evaluator.SquareInplace(encrypted);
            Console.WriteLine($"Size after squaring: {encrypted.Size}");
            Console.WriteLine($"Noise budget after squaring: {decryptor.InvariantNoiseBudget(encrypted)} bits");

            evaluator.RelinearizeInplace(encrypted, relinKeys60);
            Console.WriteLine($"Size after relinearization: {encrypted.Size}");
            Console.WriteLine($"Noise budget after relinearizing (dbc = {relinKeys60.DecompositionBitCount}): {decryptor.InvariantNoiseBudget(encrypted)} bits");

            evaluator.SquareInplace(encrypted);
            Console.WriteLine($"Size after second squaring: {encrypted.Size}");
            Console.WriteLine($"Noise budget after second squaring: {decryptor.InvariantNoiseBudget(encrypted)} bits");

            evaluator.RelinearizeInplace(encrypted, relinKeys60);
            Console.WriteLine($"Size after relinearization: {encrypted.Size}");
            Console.WriteLine($"Noise budget after relinearizing (dbc = {relinKeys60.DecompositionBitCount}): {decryptor.InvariantNoiseBudget(encrypted)} bits");

            decryptor.Decrypt(encrypted, plain2);
            Console.WriteLine($"Fourth power: {plain2.ToString()}");
            Console.WriteLine();

            /*
            Observe from the print-out that we have now used significantly more of our
            noise budget than in the two previous runs. This is again not surprising, 
            since the first relinearization chops off a huge part of the noise budget.

            However, note that the second relinearization does not change the noise
            budget by any observable amount. This is very important to understand when
            optimal performance is desired: relinearization always drops the noise
            budget from the maximum (freshly encrypted ciphertext) down to a fixed 
            amount depending on the encryption parameters and the decomposition bit 
            count. On the other hand, homomorphic multiplication always consumes the
            noise budget from its current level. This is why the second relinearization
            does not change the noise budget anymore: it is already consumed past the
            fixed amount determinted by the decomposition bit count and the encryption
            parameters. 

            We now perform a third squaring and observe an even further compounded
            decrease in the noise budget. Again, relinearization does not consume the
            noise budget at this point by any observable amount, even with the largest
            possible decomposition bit count.
            */
            evaluator.SquareInplace(encrypted);
            Console.WriteLine($"Size after third squaring: {encrypted.Size}");
            Console.WriteLine($"Noise budget after third squaring: {decryptor.InvariantNoiseBudget(encrypted)} bits");

            evaluator.RelinearizeInplace(encrypted, relinKeys60);
            Console.WriteLine($"Size after relinearization: {encrypted.Size}");
            Console.WriteLine($"Noise budget after relinearizing (dbc = {relinKeys60.DecompositionBitCount}): {decryptor.InvariantNoiseBudget(encrypted)} bits");

            decryptor.Decrypt(encrypted, plain2);
            Console.WriteLine($"Eigth power: {plain2.ToString()}");

            /*
            Observe from the print-out that the polynomial coefficients are no longer
            correct as integers: they have been reduced modulo PlainModulus, and there
            was no warning sign about this. It might be necessary to carefully analyze
            the computation to make sure such overflow does not occur unexpectedly.

            These experiments suggest that an optimal strategy might be to relinearize
            first with relinearization keys with a small decomposition bit count, and 
            later with relinearization keys with a larger decomposition bit count (for 
            performance) when noise budget has already been consumed past the bound 
            determined by the larger decomposition bit count. For example, the best 
            strategy might have been to use relinKeys16 in the first relinearization 
            and relinKeys60 in the next two relinearizations for optimal noise budget 
            consumption/performance trade-off. Luckily, in most use-cases it is not so 
            critical to squeeze out every last bit of performance, especially when 
            larger parameters are used.
            */
        }

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

        private static void ExampleBFVBasicsIV()
        {
            Utilities.PrintExampleBanner("Example: BFV Basics IV");

            /*
            In this example we describe the concept of `ParmsId' in the context of the
            BFV scheme and show how modulus switching can be used for improving both
            computation and communication cost.

            We start by setting up medium size parameters for BFV as usual.
            */
            EncryptionParameters parms = new EncryptionParameters(SchemeType.BFV)
            {
                PolyModulusDegree = 8192,
                CoeffModulus = DefaultParams.CoeffModulus128(polyModulusDegree: 8192),
                PlainModulus = new SmallModulus(1 << 20)
            };

            /*
            In Microsoft SEAL a particular set of encryption parameters (excluding the random
            number generator) is identified uniquely by a SHA-3 hash of the parameters.
            This hash is called the `ParmsId' and can be easily accessed and printed
            at any time. The hash will change as soon as any of the relevant parameters
            is changed.
            */
            Console.WriteLine($"Current ParmsId: {parms.ParmsId}");
            Console.WriteLine("Changing PlainModulus...");
            parms.SetPlainModulus((1 << 20) + 1);
            Console.WriteLine($"Current ParmsId: {parms.ParmsId}");
            Console.WriteLine();

            /*
            Create the context.
            */
            SEALContext context = SEALContext.Create(parms);
            Utilities.PrintParameters(context);

            /*
            All keys and ciphertext, and in the CKKS also plaintexts, carry the ParmsId
            for the encryption parameters they are created with, allowing Microsoft SEAL to very 
            quickly determine whether the objects are valid for use and compatible for 
            homomorphic computations. Microsoft SEAL takes care of managing, and verifying the 
            ParmsId for all objects so the user should have no reason to change it by 
            hand. 
            */
            KeyGenerator keygen = new KeyGenerator(context);
            PublicKey publicKey = keygen.PublicKey;
            SecretKey secretKey = keygen.SecretKey;
            Console.WriteLine($"ParmsId of public key: {publicKey.ParmsId}");
            Console.WriteLine($"ParmsId of secret key: {secretKey.ParmsId}");

            Encryptor encryptor = new Encryptor(context, publicKey);
            Evaluator evaluator = new Evaluator(context);
            Decryptor decryptor = new Decryptor(context, secretKey);

            /*
            Note how in the BFV scheme plaintexts do not carry the ParmsId, but 
            ciphertexts do.
            */
            Plaintext plain = new Plaintext("1x^3 + 2x^2 + 3x^1 + 4");
            Ciphertext encrypted = new Ciphertext();
            encryptor.Encrypt(plain, encrypted);
            Console.WriteLine($"ParmsId of plain: {plain.ParmsId} (not set)");
            Console.WriteLine($"ParmsId of encrypted: {encrypted.ParmsId}");
            Console.WriteLine();

            /*
            When SEALContext is created from a given EncryptionParameters instance,
            Microsoft SEAL automatically creates a so-called "modulus switching chain", which is
            a chain of other encryption parameters derived from the original set.
            The parameters in the modulus switching chain are the same as the original 
            parameters with the exception that size of the coefficient modulus is
            decreasing going down the chain. More precisely, each parameter set in the
            chain attempts to remove one of the coefficient modulus primes from the
            previous set; this continues until the parameter set is no longer valid
            (e.g. PlainModulus is larger than the remaining CoeffModulus). It is easy
            to walk through the chain and access all the parameter sets. Additionally,
            each parameter set in the chain has a `ChainIndex' that indicates its
            position in the chain so that the last set has index 0. We say that a set
            of encryption parameters, or an object carrying those encryption parameters,
            is at a higher level in the chain than another set of parameters if its the
            chain index is bigger, i.e. it is earlier in the chain. 
            */
            SEALContext.ContextData contextData;
            for (contextData = context.FirstContextData; null != contextData; contextData = contextData.NextContextData)
            {
                Console.WriteLine($"Chain index: {contextData.ChainIndex}");
                Console.WriteLine($"ParmsId: {contextData.Parms.ParmsId}");
                Console.Write("Coeff Modulus primes: ");
                //for (const auto &prime : context_data->parms().CoeffModulus())
                //{
                //cout << prime.value() << " ";
                //}

                foreach (var prime in contextData.Parms.CoeffModulus)
                {
                    Console.Write($"{Utilities.ULongToString(prime.Value)} ");
                }
                Console.WriteLine();
                Console.WriteLine("\\");
                Console.WriteLine(" \\-->");
            }
            Console.WriteLine("End of chain reached");
            Console.WriteLine();

            /*
            Modulus switching changes the ciphertext parameters to any set down the
            chain from the current one. The function ModSwitchToNext(...) always
            switches to the next set down the chain, whereas ModSwitchTo(...) switches
            to a parameter set down the chain corresponding to a given ParmsId.
            */
            contextData = context.FirstContextData;
            while (null != contextData.NextContextData)
            {
                Console.WriteLine($"Chain index: {contextData.ChainIndex}");
                Console.WriteLine($"ParmsId of encrypted: {encrypted.ParmsId}");
                Console.WriteLine($"Noise budget at this level: {decryptor.InvariantNoiseBudget(encrypted)} bits");
                Console.WriteLine("\\");
                Console.WriteLine(" \\-->");
                evaluator.ModSwitchToNextInplace(encrypted);
                contextData = contextData.NextContextData;
            }

            Console.WriteLine($"Chain index: {contextData.ChainIndex}");
            Console.WriteLine($"ParmsId of encrypted: {encrypted.ParmsId}");
            Console.WriteLine($"Noise budget at this level: {decryptor.InvariantNoiseBudget(encrypted)} bits");
            Console.WriteLine("\\");
            Console.WriteLine(" \\-->");
            Console.WriteLine("End of chain reached");
            Console.WriteLine();

            /*
            At this point it is hard to see any benefit in doing this: we lost a huge 
            amount of noise budget (i.e. computational power) at each switch and seemed
            to get nothing in return. The ciphertext still decrypts to the exact same
            value.
            */
            decryptor.Decrypt(encrypted, plain);
            Console.WriteLine($"Decryption: {plain.ToString()}");
            Console.WriteLine();

            /*
            However, there is a hidden benefit: the size of the ciphertext depends
            linearly on the number of primes in the coefficient modulus. Thus, if there 
            is no need or intention to perform any more computations on a given 
            ciphertext, we might as well switch it down to the smallest (last) set of 
            parameters in the chain before sending it back to the secret key holder for 
            decryption.

            Also the lost noise budget is actually not as issue at all, if we do things
            right, as we will see below. First we recreate the original ciphertext (with 
            largest parameters) and perform some simple computations on it.
            */
            encryptor.Encrypt(plain, encrypted);
            RelinKeys relinKeys = keygen.RelinKeys(decompositionBitCount: DefaultParams.DBCmax);
            Console.WriteLine($"Noise budget before squaring: {decryptor.InvariantNoiseBudget(encrypted)} bits");
            evaluator.SquareInplace(encrypted);
            evaluator.RelinearizeInplace(encrypted, relinKeys);
            Console.WriteLine($"Noise budget after squaring: {decryptor.InvariantNoiseBudget(encrypted)} bits");

            /*
            From the print-out we see that the noise budget after these computations is 
            just slightly below the level we would have in a fresh ciphertext after one 
            modulus switch (135 bits). Surprisingly, in this case modulus switching has 
            no effect at all on the modulus.
            */
            evaluator.ModSwitchToNextInplace(encrypted);
            Console.WriteLine($"Noise budget after modulus switching: {decryptor.InvariantNoiseBudget(encrypted)} bits");

            /*
            This means that there is no harm at all in dropping some of the coefficient
            modulus after doing enough computations. In some cases one might want to
            switch to a lower level slightly earlier, actually sacrificing some of the 
            noise budget in the process, to gain computational performance from having
            a smaller coefficient modulus. We see from the print-out that that the next 
            modulus switch should be done ideally when the noise budget reaches 81 bits. 
            */
            evaluator.SquareInplace(encrypted);
            evaluator.RelinearizeInplace(encrypted, relinKeys);
            Console.WriteLine($"Noise budget after squaring: {decryptor.InvariantNoiseBudget(encrypted)} bits");
            evaluator.ModSwitchToNextInplace(encrypted);
            Console.WriteLine($"Noise budget after modulus switching: {decryptor.InvariantNoiseBudget(encrypted)} bits");
            evaluator.SquareInplace(encrypted);
            evaluator.RelinearizeInplace(encrypted, relinKeys);
            Console.WriteLine($"Noise budget after squaring: {decryptor.InvariantNoiseBudget(encrypted)} bits");
            evaluator.ModSwitchToNextInplace(encrypted);
            Console.WriteLine($"Noise budget after modulus switching: {decryptor.InvariantNoiseBudget(encrypted)} bits");
            Console.WriteLine();

            /*
            At this point the ciphertext still decrypts correctly, has very small size,
            and the computation was as efficient as possible. Note that the decryptor
            can be used to decrypt a ciphertext at any level in the modulus switching
            chain as long as the secret key is at a higher level in the same chain.
            */
            decryptor.Decrypt(encrypted, plain);
            Console.WriteLine($"Decryption of eighth power: {plain.ToString()}");
            Console.WriteLine();

            /*
            In BFV modulus switching is not necessary and in some cases the user might
            not want to create the modulus switching chain. This can be done by passing
            a bool `false' to the SEALContext.Create(...) function as follows.
            */
            context = SEALContext.Create(parms, expandModChain: false);

            /*
            We can check that indeed the modulus switching chain has not been created.
            The following loop should execute only once.
            */
            for (contextData = context.FirstContextData; null != contextData; contextData = contextData.NextContextData)
            {
                Console.WriteLine($"Chain index: {contextData.ChainIndex}");
                Console.WriteLine($"ParmsId: {contextData.Parms.ParmsId}");
                Console.Write("CoeffModulus primes: ");

                foreach (SmallModulus prime in contextData.Parms.CoeffModulus)
                {
                    Console.Write($"{Utilities.ULongToString(prime.Value)} ");
                }

                Console.WriteLine();
                Console.WriteLine("\\");
                Console.WriteLine(" \\-->");
            }

            Console.WriteLine("End of chain reached");

            /*
            It is very important to understand how this example works since in the CKKS 
            scheme modulus switching has a much more fundamental purpose and the next 
            examples will be difficult to understand unless these basic properties are 
            totally clear.
            */
        }

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
                double micros = timer.Elapsed.TotalMilliseconds * 1000;
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
                micros = timer.Elapsed.TotalMilliseconds * 1000;
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

                double avgBatch = timeBatchSum.Elapsed.TotalMilliseconds * 1000 / count;
                double avgUnbatch = timeUnbatchSum.Elapsed.TotalMilliseconds * 1000 / count;
                double avgEncrypt = timeEncryptSum.Elapsed.TotalMilliseconds * 1000 / count;
                double avgDecrypt = timeDecryptSum.Elapsed.TotalMilliseconds * 1000 / count;
                double avgAdd = timeAddSum.Elapsed.TotalMilliseconds * 1000 / count;
                double avgMultiply = timeMultiplySum.Elapsed.TotalMilliseconds * 1000 / count;
                double avgMultiplyPlain = timeMultiplyPlainSum.Elapsed.TotalMilliseconds * 1000 / count;
                double avgSquare = timeSquareSum.Elapsed.TotalMilliseconds * 1000 / count;
                double avgRelinearize = timeRelinearizeSum.Elapsed.TotalMilliseconds * 1000 / count;
                double avgRotateRowsOneStep = timeRotateRowsOneStepSum.Elapsed.TotalMilliseconds * 1000 / count;
                double avgRotateRowsRandom = timeRotateRowsRandomSum.Elapsed.TotalMilliseconds * 1000 / count;
                double avgRotateColumns = timeRotateColumnsSum.Elapsed.TotalMilliseconds * 1000 / count;

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

        private static void ExampleCKKSBasicsI()
        {
            Utilities.PrintExampleBanner("Example: CKKS Basics ");

            /*
            In this example we demonstrate using the Cheon-Kim-Kim-Song (CKKS) scheme
            for encrypting and computing on floating point numbers. For full details on 
            the CKKS scheme, we refer the reader to https://eprint.iacr.org/2016/421.
            For better performance, Microsoft SEAL implements the "FullRNS" optimization for CKKS 
            described in https://eprint.iacr.org/2018/931.
            */

            /*
            We start by creating encryption parameters for the CKKS scheme. One major
            difference to the BFV scheme is that the CKKS scheme does not use the
            PlainModulus parameter.
            */
            EncryptionParameters parms = new EncryptionParameters(SchemeType.CKKS);
            parms.PolyModulusDegree = 8192;
            parms.CoeffModulus = DefaultParams.CoeffModulus128(polyModulusDegree: 8192);

            /*
            We create the SEALContext as usual and print the parameters.
            */
            SEALContext context = SEALContext.Create(parms);
            Utilities.PrintParameters(context);

            /*
            Keys are created the same way as for the BFV scheme.
            */
            KeyGenerator keygen = new KeyGenerator(context);
            PublicKey publicKey = keygen.PublicKey;
            SecretKey secretKey = keygen.SecretKey;
            RelinKeys relinKeys = keygen.RelinKeys(decompositionBitCount: DefaultParams.DBCmax);

            /*
            We also set up an Encryptor, Evaluator, and Decryptor as usual.
            */
            Encryptor encryptor = new Encryptor(context, publicKey);
            Evaluator evaluator = new Evaluator(context);
            Decryptor decryptor = new Decryptor(context, secretKey);

            /*
            To create CKKS plaintexts we need a special encoder: we cannot create them
            directly from polynomials. Note that the IntegerEncoder, FractionalEncoder, 
            and BatchEncoder cannot be used with the CKKS scheme. The CKKS scheme allows 
            encryption and approximate computation on vectors of real or complex numbers 
            which the CKKSEncoder converts into Plaintext objects. At a high level this 
            looks a lot like BatchEncoder for the BFV scheme, but the theory behind it
            is different.
            */
            CKKSEncoder encoder = new CKKSEncoder(context);

            /*
            In CKKS the number of slots is PolyModulusDegree / 2 and each slot encodes 
            one complex (or real) number. This should be contrasted with BatchEncoder in
            the BFV scheme, where the number of slots is equal to PolyModulusDegree 
            and they are arranged into a 2-by-(PolyModulusDegree / 2) matrix. 
            */
            ulong slotCount = encoder.SlotCount;
            Console.WriteLine($"Number of slots: {slotCount}");

            /*
            We create a small vector to encode; the CKKSEncoder will implicitly pad it 
            with zeros to full size (PolyModulusDegree / 2) when encoding. 
            */
            List<double> input = new List<double> { 0.0, 1.1, 2.2, 3.3 };
            Console.WriteLine("Input vector: ");
            Utilities.PrintVector(input);

            /*
            Now we encode it with CKKSEncoder. The floating-point coefficients of input
            will be scaled up by the parameter `scale'; this is necessary since even in
            the CKKS scheme the plaintexts are polynomials with integer coefficients. 
            It is instructive to think of the scale as determining the bit-precision of 
            the encoding; naturally it will also affect the precision of the result. 

            In CKKS the message is stored modulo CoeffModulus (in BFV it is stored 
            modulo PlainModulus), so the scale must not get too close to the total size 
            of CoeffModulus. In this case our CoeffModulus is quite large (218 bits) 
            so we have little to worry about in this regard. For this example a 60-bit 
            scale is more than enough.
            */
            Plaintext plain = new Plaintext();
            double scale = Math.Pow(2.0, 60);
            encoder.Encode(input, scale, plain);

            /*
            The vector is encrypted the same was as in BFV.
            */
            Ciphertext encrypted = new Ciphertext();
            encryptor.Encrypt(plain, encrypted);

            /*
            Another difference to the BFV scheme is that in CKKS also plaintexts are
            linked to specific parameter sets: they carry the corresponding ParmsId.
            An overload of CKKSEncoder.Encode(...) allows the caller to specify which
            parameter set in the modulus switching chain (identified by ParmsId) should 
            be used to encode the plaintext. This is important as we will see later.
            */
            Console.WriteLine($"ParmsId of plain: {plain.ParmsId}");
            Console.WriteLine($"ParmsId of encrypted: {encrypted.ParmsId}");
            Console.WriteLine();

            /*
            The ciphertexts will keep track of the scales in the underlying plaintexts.
            The current scale in every plaintext and ciphertext is easy to access.
            */
            Console.WriteLine($"Scale in plain: {plain.Scale}");
            Console.WriteLine($"Scale in encrypted: {encrypted.Scale}");
            Console.WriteLine();

            /*
            Basic operations on the ciphertexts are still easy to do. Here we square 
            the ciphertext, decrypt, decode, and print the result. We note also that 
            decoding returns a vector of full size (PolyModulusDegree / 2); this is 
            because of the implicit zero-padding mentioned above. 
            */
            evaluator.SquareInplace(encrypted);
            evaluator.RelinearizeInplace(encrypted, relinKeys);
            decryptor.Decrypt(encrypted, plain);
            encoder.Decode(plain, input);
            Console.WriteLine("Squared input:");
            Utilities.PrintVector(input);

            /*
            We notice that the results are correct. We can also print the scale in the 
            result and observe that it has increased. In fact, it is now the square of 
            the original scale (2^60). 
            */
            Console.WriteLine($"Scale in the square: {encrypted.Scale} ({(int)Math.Ceiling(Math.Log(encrypted.Scale, newBase: 2))} bits)");

            /*
            CKKS supports modulus switching just like the BFV scheme. We can switch
            away parts of the coefficient modulus.
            */
            Console.WriteLine($"Current CoeffModulus size: {context.GetContextData(encrypted.ParmsId).TotalCoeffModulusBitCount} bits");
            Console.WriteLine("Modulus switching...");
            evaluator.ModSwitchToNextInplace(encrypted);
            Console.WriteLine($"Current CoeffModulus size: {context.GetContextData(encrypted.ParmsId).TotalCoeffModulusBitCount} bits");
            Console.WriteLine();

            /*
            At this point if we tried switching further Microsoft SEAL would throw an exception.
            This is because the scale is 120 bits and after modulus switching we would
            be down to a total CoeffModulus smaller than that, which is not enough to
            contain the plaintext. We decrypt and decode, and observe that the result 
            is the same as before. 
            */
            decryptor.Decrypt(encrypted, plain);
            encoder.Decode(plain, input);
            Console.WriteLine("Squared input:");
            Utilities.PrintVector(input);

            /*
            In some cases it can be convenient to change the scale of a ciphertext by
            hand. For example, multiplying the scale by a number effectively divides the 
            underlying plaintext by that number, and vice versa. The caveat is that the 
            resulting scale can be incompatible with the scales of other ciphertexts.
            Here we divide the ciphertext by 3.
            */
            encrypted.Scale *= 3;
            decryptor.Decrypt(encrypted, plain);
            encoder.Decode(plain, input);
            Console.WriteLine("Divided by 3:");
            Utilities.PrintVector(input);

            /*
            Homomorphic addition and subtraction naturally require that the scales of
            the inputs are the same, but also that the encryption parameters (ParmsId)
            are the same. Here we add a plaintext to encrypted. Note that a scale or
            ParmsId mismatch would make Evaluator.AddPlain(..) throw an exception;
            there is no problem here since we encode the plaintext just-in-time with
            exactly the right scale.
            */
            List<double> summand = new List<double> { 20.2, 30.3, 40.4, 50.5 };
            Console.WriteLine("Plaintext summand:");
            Utilities.PrintVector(summand);

            /*
            Get the ParmsId and scale from encrypted and do the addition.
            */
            Plaintext plainSummand = new Plaintext();
            encoder.Encode(summand, encrypted.ParmsId, encrypted.Scale,
                plainSummand);
            evaluator.AddPlainInplace(encrypted, plainSummand);

            /*
            Decryption and decoding should give the correct result.
            */
            decryptor.Decrypt(encrypted, plain);
            encoder.Decode(plain, input);
            Console.WriteLine("Sum:");
            Utilities.PrintVector(input);

            /*
            Note that we have not mentioned noise budget at all. In fact, CKKS does not
            have a similar concept of a noise budget as BFV; instead, the homomorphic
            encryption noise will overlap the low-order bits of the message. This is why
            scaling is needed: the message must be moved to higher-order bits to protect
            it from the noise. Still, it is difficult to completely decouple the noise 
            from the message itself; hence the noise/error budget cannot be exactly 
            measured from a ciphertext alone. 
            */
        }

        private static void ExampleCKKSBasicsII()
        {
            Utilities.PrintExampleBanner("Example: CKKS Basics II");

            /*
            The previous example did not really make it clear why CKKS is useful at all.
            Certainly one can scale floating-point numbers to integers, encrypt them,
            keep track of the scale, and operate on them by just using BFV. The problem
            with this approach is that the scale quickly grows larger than the size of
            the coefficient modulus, preventing further computations. The true power of 
            CKKS is that it allows the scale to be switched down (`rescaling') without 
            changing the encrypted values. 

            To demonstrate this, we start by setting up the same environment we had in 
            the previous example.
            */
            EncryptionParameters parms = new EncryptionParameters(SchemeType.CKKS);
            parms.PolyModulusDegree = 8192;
            parms.CoeffModulus = DefaultParams.CoeffModulus128(polyModulusDegree: 8192);

            SEALContext context = SEALContext.Create(parms);
            Utilities.PrintParameters(context);

            KeyGenerator keygen = new KeyGenerator(context);
            PublicKey publicKey = keygen.PublicKey;
            SecretKey secretKey = keygen.SecretKey;
            RelinKeys relinKeys = keygen.RelinKeys(decompositionBitCount: DefaultParams.DBCmax);

            Encryptor encryptor = new Encryptor(context, publicKey);
            Evaluator evaluator = new Evaluator(context);
            Decryptor decryptor = new Decryptor(context, secretKey);

            CKKSEncoder encoder = new CKKSEncoder(context);

            ulong slotCount = encoder.SlotCount;
            Console.WriteLine($"Number of slots: {slotCount}");

            List<double> input = new List<double> { 0.0, 1.1, 2.2, 3.3 };
            Console.WriteLine("Input vector:");
            Utilities.PrintVector(input);

            /*
            We use a slightly smaller scale in this example.
            */
            Plaintext plain = new Plaintext();
            double scale = Math.Pow(2.0, 60);
            encoder.Encode(input, scale, plain);

            Ciphertext encrypted = new Ciphertext();
            encryptor.Encrypt(plain, encrypted);

            /*
            Print the scale and the ParmsId for encrypted.
            */
            Console.WriteLine($"Chain index of (encryption parameters of) encrypted: {context.GetContextData(encrypted.ParmsId).ChainIndex}");
            Console.WriteLine($"Scale in encrypted before squaring: {encrypted.Scale}");

            /*
            We did this already in the previous example: square encrypted and observe 
            the scale growth.
            */
            evaluator.SquareInplace(encrypted);
            evaluator.RelinearizeInplace(encrypted, relinKeys);
            Console.WriteLine($"Scale in encrypted after squaring: {encrypted.Scale} ({(int)Math.Ceiling(Math.Log(encrypted.Scale, newBase: 2))} bits)");
            Console.WriteLine($"Current CoeffModulus size: {context.GetContextData(encrypted.ParmsId).TotalCoeffModulusBitCount} bits");
            Console.WriteLine();

            /*
            Now, to prevent the scale from growing too large in subsequent operations,
            we apply rescaling.
            */
            Console.WriteLine("Rescaling ...");
            evaluator.RescaleToNextInplace(encrypted);
            Console.WriteLine();

            /*
            Rescaling changes the coefficient modulus as modulus switching does. These
            operations are in fact very closely related. Moreover, the scale indeed has 
            been significantly reduced: rescaling divides the scale by the coefficient
            modulus prime that was switched away. Since our coefficient modulus in this
            case consisted of the primes (see seal/utils/global.cpp)

                0x7fffffff380001,  0x7ffffffef00001,
                0x3fffffff000001,  0x3ffffffef40001,

            the last of which is 54 bits, the bit-size of the scale was reduced by 
            precisely 54 bits. Finer granularity rescaling would require smaller primes
            to be used, but this might lead to performance problems as the computational 
            cost of homomorphic operations and the size of ciphertexts depends linearly 
            on the number of primes in CoeffModulus.
            */
            Console.WriteLine($"Chain index of (encryption parameters of) encrypted: {context.GetContextData(encrypted.ParmsId).ChainIndex}");
            Console.WriteLine($"Scale in encrypted: {encrypted.Scale} ({(int)Math.Ceiling(Math.Log(encrypted.Scale, newBase: 2))} bits)");
            Console.WriteLine($"Current CoeffModulus size: {context.GetContextData(encrypted.ParmsId).TotalCoeffModulusBitCount} bits");
            Console.WriteLine();

            /*
            We can even compute the fourth power of the input. Note that it is very
            important to first relinearize and then rescale. Trying to do these two
            operations in the opposite order will make Microsoft SEAL throw and exception.
            */
            Console.WriteLine("Squaring and rescaling ...");
            Console.WriteLine();
            evaluator.SquareInplace(encrypted);
            evaluator.RelinearizeInplace(encrypted, relinKeys);
            evaluator.RescaleToNextInplace(encrypted);

            Console.WriteLine($"Chain index of (encryption parameters of) encrypted: {context.GetContextData(encrypted.ParmsId).ChainIndex}");
            Console.WriteLine($"Scale in encrypted: {encrypted.Scale} ({(int)Math.Ceiling(Math.Log(encrypted.Scale, newBase: 2))} bits)");
            Console.WriteLine($"Current CoeffModulus size: {context.GetContextData(encrypted.ParmsId).TotalCoeffModulusBitCount} bits");
            Console.WriteLine();

            /*
            At this point our scale is 78 bits and the coefficient modulus is 110 bits.
            This means that we cannot square the result anymore, but if we rescale once
            more and then square, things should work out better. We cannot relinearize
            with relin_keys at this point due to the large decomposition bit count we 
            used: the noise from relinearization would completely destroy our result 
            due to the small scale we are at.
            */
            Console.WriteLine("Rescaling and squaring (no relinearization) ...");
            Console.WriteLine();
            evaluator.RescaleToNextInplace(encrypted);
            evaluator.SquareInplace(encrypted);

            Console.WriteLine($"Chain index of (encryption parameters of) encrypted: {context.GetContextData(encrypted.ParmsId).ChainIndex}");
            Console.WriteLine($"Scale in encrypted: {encrypted.Scale} ({(int)Math.Ceiling(Math.Log(encrypted.Scale, newBase: 2))} bits)");
            Console.WriteLine($"Current CoeffModulus size: {context.GetContextData(encrypted.ParmsId).TotalCoeffModulusBitCount} bits");
            Console.WriteLine();

            /*
            We decrypt, decode, and print the results.
            */
            decryptor.Decrypt(encrypted, plain);
            List<double> result = new List<double>();
            encoder.Decode(plain, result);
            Console.WriteLine("Eighth powers:");
            Utilities.PrintVector(result);

            /*
            We have gone pretty low in the scale at this point and can no longer expect
            to get entirely accurate results. Still, our results are quite accurate. 
            */
            List<double> preciseResult = new List<double>();
            foreach (double d in input)
            {
                preciseResult.Add(Math.Pow(d, 8));
            }
            Console.WriteLine("Precise result:");
            Utilities.PrintVector(preciseResult);
        }

        private static void ExampleCKKSBasicsIII()
        {
            Utilities.PrintExampleBanner("Example: CKKS Basics III");

            /*
            In this example we demonstrate evaluating a polynomial function on
            floating-point input data. The challenges we encounter will be related to
            matching scales and encryption parameters when adding together terms of
            different degrees in the polynomial evaluation. We start by setting up an
            environment similar to what we had in the above examples.
            */
            EncryptionParameters parms = new EncryptionParameters(SchemeType.CKKS);
            parms.PolyModulusDegree = 8192;

            /*
            In this example we decide to use four 40-bit moduli for more flexible 
            rescaling. Note that 4*40 bits = 160 bits, which is well below the size of 
            the default coefficient modulus (see seal/util/globals.cpp). It is always
            more secure to use a smaller coefficient modulus while keeping the degree of
            the polynomial modulus fixed. Since the CoeffMod128(8192) default 218-bit 
            coefficient modulus achieves already a 128-bit security level, this 160-bit 
            modulus must be much more secure.

            We use the SmallMods40bit(int) function to get primes from a hard-coded 
            list of 40-bit prime numbers; it is important that all primes used for the
            coefficient modulus are distinct.
            */
            parms.CoeffModulus = new List<SmallModulus>
            {
                DefaultParams.SmallMods40Bit(0),
                DefaultParams.SmallMods40Bit(1),
                DefaultParams.SmallMods40Bit(2),
                DefaultParams.SmallMods40Bit(3)
            };

            SEALContext context = SEALContext.Create(parms);
            Utilities.PrintParameters(context);

            KeyGenerator keygen = new KeyGenerator(context);
            PublicKey publicKey = keygen.PublicKey;
            SecretKey secretKey = keygen.SecretKey;
            RelinKeys relinKeys = keygen.RelinKeys(decompositionBitCount: DefaultParams.DBCmax);

            Encryptor encryptor = new Encryptor(context, publicKey);
            Evaluator evaluator = new Evaluator(context);
            Decryptor decryptor = new Decryptor(context, secretKey);

            CKKSEncoder encoder = new CKKSEncoder(context);
            ulong slotCount = encoder.SlotCount;
            Console.WriteLine($"Number of slots: {slotCount}");
            Console.WriteLine();

            /*
            In this example our goal is to evaluate the polynomial PI*x^3 + 0.4x + 1 on 
            an encrypted input x for 4096 equidistant points x in the interval [0, 1]. 
            */
            List<double> input = new List<double>();
            input.Capacity = (int)slotCount;
            double currPoint = 0, stepSize = 1.0 / (slotCount - 1);
            for (ulong i = 0; i < slotCount; i++, currPoint += stepSize)
            {
                input.Add(currPoint);
            }
            Console.WriteLine("Input vector:");
            Utilities.PrintVector(input, 3);
            Console.WriteLine("Evaluating polynomial PI*x^3 + 0.4x + 1 ...");
            Console.WriteLine();

            /*
            Now encode and encrypt the input using the last of the CoeffModulus primes 
            as the scale for a reason that will become clear soon.
            */
            double scale = parms.CoeffModulus.Last().Value;
            Plaintext plainX = new Plaintext();
            encoder.Encode(input, scale, plainX);
            Ciphertext encryptedX1 = new Ciphertext();
            encryptor.Encrypt(plainX, encryptedX1);

            /*
            We create plaintext elements for PI, 0.4, and 1, using an overload of
            CKKSEncoder.Encode(...) that encodes the given floating-point value to
            every slot in the vector.
            */
            Plaintext plainCoeff3 = new Plaintext(),
                      plainCoeff1 = new Plaintext(),
                      plainCoeff0 = new Plaintext();
            encoder.Encode(3.14159265, scale, plainCoeff3);
            encoder.Encode(0.4, scale, plainCoeff1);
            encoder.Encode(1.0, scale, plainCoeff0);

            /*
            To compute x^3 we first compute x^2, relinearize, and rescale.
            */
            Ciphertext encryptedX3 = new Ciphertext();
            evaluator.Square(encryptedX1, encryptedX3);
            evaluator.RelinearizeInplace(encryptedX3, relinKeys);
            evaluator.RescaleToNextInplace(encryptedX3);

            /*
            Now encrypted_x3 is at different encryption parameters than encrypted_x1, 
            preventing us from multiplying them together to compute x^3. We could simply 
            switch encryptedX1 down to the next parameters in the modulus switching 
            chain. Since we still need to multiply the x^3 term with PI (plainCoeff3), 
            we instead compute PI*x first and multiply that with x^2 to obtain PI*x^3.
            This product poses no problems since both inputs are at the same scale and 
            use the same encryption parameters. We rescale afterwards to change the 
            scale back to 40 bits, which will also drop the coefficient modulus down to 
            120 bits. 
            */
            Ciphertext encryptedX1Coeff3 = new Ciphertext();
            evaluator.MultiplyPlain(encryptedX1, plainCoeff3, encryptedX1Coeff3);
            evaluator.RescaleToNextInplace(encryptedX1Coeff3);

            /*
            Since both encryptedX3 and encryptedX1Coeff3 now have the same scale and 
            use same encryption parameters, we can multiply them together. We write the 
            result to encryptedX3.
            */
            evaluator.MultiplyInplace(encryptedX3, encryptedX1Coeff3);
            evaluator.RelinearizeInplace(encryptedX3, relinKeys);
            evaluator.RescaleToNextInplace(encryptedX3);

            /*
            Next we compute the degree one term. All this requires is one MultiplyPlain 
            with plainCoeff1. We overwrite encryptedX1 with the result.
            */
            evaluator.MultiplyPlainInplace(encryptedX1, plainCoeff1);
            evaluator.RescaleToNextInplace(encryptedX1);

            /*
            Now we would hope to compute the sum of all three terms. However, there is 
            a serious problem: the encryption parameters used by all three terms are 
            different due to modulus switching from rescaling. 
            */
            Console.WriteLine("Parameters used by all three terms are different:");
            Console.WriteLine($"Modulus chain index for encryptedX3: {context.GetContextData(encryptedX3.ParmsId).ChainIndex}");
            Console.WriteLine($"Modulus chain index for encryptedX1: {context.GetContextData(encryptedX1.ParmsId).ChainIndex}");
            Console.WriteLine($"Modulus chain index for plainCoeff0: {context.GetContextData(plainCoeff0.ParmsId).ChainIndex}");
            Console.WriteLine();


            /*
            Let us carefully consider what the scales are at this point. If we denote 
            the primes in CoeffModulus as q1, q2, q3, q4 (order matters here), then all
            fresh encodings start with a scale equal to q4 (this was a choice we made 
            above). After the computations above the scale in encryptedX3 is q4^2/q3:

                * The product x^2 has scale q4^2;
                * The produt PI*x has scale q4^2;
                * Rescaling both of these by q4 (last prime) results in scale q4; 
                * Multiplication to obtain PI*x^3 raises the scale to q4^2;
                * Rescaling by q3 (last prime) yields a scale of q4^2/q3.

            The scale in both encryptedX1 and plainCoeff0 is just q4.
            */
            Console.WriteLine("Scale in encryptedX3: {0:0.0000000000}", encryptedX3.Scale);
            Console.WriteLine("Scale in encryptedX1: {0:0.0000000000}", encryptedX1.Scale);
            Console.WriteLine("Scale in plainCoeff0: {0:0.0000000000}", plainCoeff0.Scale);
            Console.WriteLine();

            /*
            There are a couple of ways to fix this this problem. Since q4 and q3 are 
            really close to each other, we could simply "lie" to Microsoft SEAL and set 
            the scales to be the same. For example, changing the scale of encryptedX3 to 
            be q4 simply means that we scale the value of encryptedX3 by q4/q3 which is 
            very close to 1; this should not result in any noticeable error. 

            Another option would be to encode 1 with scale q4, perform a MultiplyPlain 
            with encryptedX1, and finally rescale. In this case we would additionally 
            make sure to encode 1 with the appropriate encryption parameters (ParmsId). 

            A third option would be to initially encode plainCoeff1 with scale q4^2/q3. 
            Then, after multiplication with encrypted_x1 and rescaling, the result would 
            have scale q4^2/q3. Since encoding can be computationally costly, this may 
            not be a realistic option in some cases.

            In this example we will use the first (simplest) approach and simply change
            the scale of encryptedX3.
            */
            encryptedX3.Scale = encryptedX1.Scale;

            /*
            We still have a problem with mismatching encryption parameters. This is easy
            to fix by using traditional modulus switching (no rescaling). Note that we
            use here the Evaluator.ModSwitchToInplace(...) function to switch to
            encryption parameters down the chain with a specific ParmsId.
            */
            evaluator.ModSwitchToInplace(encryptedX1, encryptedX3.ParmsId);
            evaluator.ModSwitchToInplace(plainCoeff0, encryptedX3.ParmsId);

            /*
            All three ciphertexts are now compatible and can be added.
            */
            Ciphertext encryptedResult = new Ciphertext();
            evaluator.Add(encryptedX3, encryptedX1, encryptedResult);
            evaluator.AddPlainInplace(encryptedResult, plainCoeff0);

            /*
            Print the chain index and scale for encrypted_result. 
            */
            Console.WriteLine($"Modulus chain index for encrypted_result: {context.GetContextData(encryptedResult.ParmsId).ChainIndex}");
            Console.WriteLine("Scale in encryptedResult: {0:0.0000000000} ({1} bits)",
                encryptedResult.Scale,
                (int)Math.Ceiling(Math.Log(encryptedResult.Scale, newBase: 2)));

            /*
            We decrypt, decode, and print the result.
            */
            Plaintext plainResult = new Plaintext();
            decryptor.Decrypt(encryptedResult, plainResult);
            List<double> result = new List<double>();
            encoder.Decode(plainResult, result);
            Console.WriteLine("Result of PI*x^3 + 0.4x + 1:");
            Utilities.PrintVector(result, 3);

            /*
            At this point if we wanted to multiply encryptedResult one more time, the 
            other multiplicand would have to have scale less than 40 bits, otherwise 
            the scale would become larger than the CoeffModulus itself. 
            */
            Console.WriteLine($"Current CoeffModulus size for encrypted_result: {context.GetContextData(encryptedResult.ParmsId).TotalCoeffModulusBitCount} bits");
            Console.WriteLine();

            /*
            A very extreme case for multiplication is where we multiply a ciphertext 
            with a vector of values that are all the same integer. For example, let us 
            multiply encryptedResult by 7. In this case we do not need any scaling in 
            the multiplicand due to a different (much simpler) encoding process.
            */
            Plaintext plainIntegerScalar = new Plaintext();
            encoder.Encode(7, encryptedResult.ParmsId, plainIntegerScalar);
            evaluator.MultiplyPlainInplace(encryptedResult, plainIntegerScalar);

            Console.WriteLine("Scale in plainIntegerScalar scale: {0:0.0000000000}", plainIntegerScalar.Scale);
            Console.WriteLine("Scale in encryptedResult: {0:0.0000000000}", encryptedResult.Scale);

            /*
            We decrypt, decode, and print the result.
            */
            decryptor.Decrypt(encryptedResult, plainResult);
            encoder.Decode(plainResult, result);
            Console.WriteLine("Result of 7 * (PI*x^3 + 0.4x + 1):");
            Utilities.PrintVector(result, 3);

            /*
            Finally, we show how to apply vector rotations on the encrypted data. This
            is very similar to how matrix rotations work in the BFV scheme. We try this
            with three sizes of Galois keys. In some cases it is desirable for memory
            reasons to create Galois keys that support only specific rotations. This can
            be done by passing to KeyGenerator.GaloisKeys(...) a vector of signed 
            integers specifying the desired rotation step counts. Here we create Galois
            keys that only allow cyclic rotation by a single step (at a time) to the left.
            */
            GaloisKeys galKeys30 = keygen.GaloisKeys(decompositionBitCount: 30, steps: new int[] { 1 });
            GaloisKeys galKeys15 = keygen.GaloisKeys(decompositionBitCount: 15, steps: new int[] { 1 });

            Ciphertext rotatedResult = new Ciphertext();
            evaluator.RotateVector(encryptedResult, 1, galKeys15, rotatedResult);
            decryptor.Decrypt(rotatedResult, plainResult);
            encoder.Decode(plainResult, result);
            Console.WriteLine("Result rotated with dbc 15:");
            Utilities.PrintVector(result, 3);

            evaluator.RotateVector(encryptedResult, 1, galKeys30, rotatedResult);
            decryptor.Decrypt(rotatedResult, plainResult);
            encoder.Decode(plainResult, result);
            Console.WriteLine("Result rotated with dbc 30:");
            Utilities.PrintVector(result, 3);

            /*
            We notice that the using the smallest decomposition bit count introduces 
            the least amount of error in the result. The problem is that our scale at 
            this point is very small -- only 40 bits -- so a rotation with decomposition 
            bit count 30 or bigger already destroys most or all of the message bits. 
            Ideally rotations would be performed right after multiplications before any
            rescaling takes place. This way the scale is as large as possible and the
            additive noise coming from the rotation (or relinearization) will be totally
            shadowed by the large scale, and subsequently scaled down by the following 
            rescaling. Of course this may not always be possible to arrange.

            We did not show any computations on complex numbers in these examples, but
            the CKKSEncoder would allow us to have done that just as easily. Additions
            and multiplications behave just as one would expect. It is also possible
            to complex conjugate the values in a ciphertext by using the functions
            Evaluator.ComplexConjugate[Inplace](...).
            */
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

                double avgEncode = timeEncodeSum.Elapsed.TotalMilliseconds * 1000 / count;
                double avgDecode = timeDecodeSum.Elapsed.TotalMilliseconds * 1000 / count;
                double avgEncrypt = timeEncryptSum.Elapsed.TotalMilliseconds * 1000 / count;
                double avgDecrypt = timeDecryptSum.Elapsed.TotalMilliseconds * 1000 / count;
                double avgAdd = timeAddSum.Elapsed.TotalMilliseconds * 1000 / count;
                double avgMultiply = timeMultiplySum.Elapsed.TotalMilliseconds * 1000 / count;
                double avgMultiplyPlain = timeMultiplyPlainSum.Elapsed.TotalMilliseconds * 1000 / count;
                double avgSquare = timeSquareSum.Elapsed.TotalMilliseconds * 1000 / count;
                double avgRelinearize = timeRelinearizeSum.Elapsed.TotalMilliseconds * 1000 / count;
                double avgRescale = timeRescaleSum.Elapsed.TotalMilliseconds * 1000 / count;
                double avgRotateOneStep = timeRotateOneStepSum.Elapsed.TotalMilliseconds * 1000 / count;
                double avgRotateRandom = timeRotateRandomSum.Elapsed.TotalMilliseconds * 1000 / count;
                double avgConjugate = timeConjugateSum.Elapsed.TotalMilliseconds * 1000 / count;

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

        static void Main(string[] args)
        {
            while (true)
            {
                Console.WriteLine();
                Console.WriteLine("Microsoft SEAL Examples:");
                Console.WriteLine(" 1. BFV Basics I");
                Console.WriteLine(" 2. BFV Basics II");
                Console.WriteLine(" 3. BFV Basics III");
                Console.WriteLine(" 4. BFV Basics IV");
                Console.WriteLine(" 5. BFV Performance Test");
                Console.WriteLine(" 6. CKKS Basics I");
                Console.WriteLine(" 7. CKKS Basics II");
                Console.WriteLine(" 8. CKKS Basics III");
                Console.WriteLine(" 9. CKKS Performance Test");
                Console.WriteLine(" 0. Exit");
                Console.WriteLine();

                /*
                Print how much memory we have allocated from the current memory pool.
                By default the memory pool will be a static global pool and the
                MemoryManager class can be used to change it. Most users should have
                little or no reason to touch the memory allocation system.
                */
                ulong megabytes = MemoryManager.GetPool().AllocByteCount >> 20;
                Console.WriteLine($"Total memory allocated from the current memory pool: {megabytes} MB");
                Console.WriteLine();
                Console.Write("Run example: ");

                ConsoleKeyInfo key;
                do
                {
                    key = Console.ReadKey();
                } while (key.KeyChar < '0' || key.KeyChar > '9');
                Console.WriteLine();

                switch (key.Key)
                {
                    case ConsoleKey.D1:
                        ExampleBFVBasicsI();
                        break;

                    case ConsoleKey.D2:
                        ExampleBFVBasicsII();
                        break;

                    case ConsoleKey.D3:
                        ExampleBFVBasicsIII();
                        break;

                    case ConsoleKey.D4:
                        ExampleBFVBasicsIV();
                        break;

                    case ConsoleKey.D5:
                        ExampleBFVPerformance();
                        break;

                    case ConsoleKey.D6:
                        ExampleCKKSBasicsI();
                        break;

                    case ConsoleKey.D7:
                        ExampleCKKSBasicsII();
                        break;

                    case ConsoleKey.D8:
                        ExampleCKKSBasicsIII();
                        break;

                    case ConsoleKey.D9:
                        ExampleCKKSPerformance();
                        break;

                    case ConsoleKey.D0:
                        return;

                    default:
                        Console.WriteLine("Invalid option.");
                        break;
                }

                /*
                Force a garbage collection after each example to accurately show memory pool use.
                */
                GC.Collect();
            }
        }
    }
}
