using Microsoft.Research.SEAL;
using System;
using System.Collections;
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

            SEAL implements two encryption schemes: the Brakerski/Fan-Vercauteren (BFV) 
            scheme and the Cheon-Kim-Kim-Song (CKKS) scheme. In the first examples we 
            use the BFV scheme as it is far easier to understand and use than CKKS. For 
            more details on the basics of the BFV scheme, we refer the reader to the
            original paper https://eprint.iacr.org/2012/144. In truth, to achieve good 
            performance SEAL implements the "FullRNS" optimization as described in 
            https://eprint.iacr.org/2016/510, but this optiomization is invisible to 
            the user and has no security implications. We will discuss the CKKS scheme
            in later examples.

            The first task is to set up an instance of the EncryptionParameters class.
            It is critical to understand how these different parameters behave, how they
            affect the encryption scheme, performance, and the security level. There are 
            three encryption parameters that are necessary to set: 

                - poly_modulus_degree (degree of polynomial modulus);
                - coeff_modulus ([ciphertext] coefficient modulus);
                - plain_modulus (plaintext modulus).

            A fourth parameter -- noise_standard_deviation -- has a default value 3.20 
            and should not be necessary to modify unless the user has a specific reason 
            to do so and has an in-depth understanding of the security implications.

            A fifth parameter -- random_generator -- can be set to use customized random
            number generators. By default, SEAL uses hardware-based AES in counter mode
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
            Next we set the [ciphertext] coefficient modulus (coeff_modulus). The size 
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

                coeff_modulus_128bit(int)
                coeff_modulus_192bit(int)
                coeff_modulus_256bit(int)

            for 128-bit, 192-bit, and 256-bit security levels. The integer parameter is 
            the degree of the polynomial modulus used.

            In SEAL the coefficient modulus is a positive composite number -- a product
            of distinct primes of size up to 60 bits. When we talk about the size of the 
            coefficient modulus we mean the bit length of the product of the primes. The 
            small primes are represented by instances of the SmallModulus class so for
            example coeff_modulus_128bit(int) returns a vector of SmallModulus instances. 

            It is possible for the user to select their own small primes. Since SEAL uses
            the Number Theoretic Transform (NTT) for polynomial multiplications modulo the
            factors of the coefficient modulus, the factors need to be prime numbers
            congruent to 1 modulo 2*poly_modulus_degree. We have generated a list of such
            prime numbers of various sizes that the user can easily access through the
            functions 

                small_mods_60bit(int)
                small_mods_50bit(int)
                small_mods_40bit(int)
                small_mods_30bit(int)

            each of which gives access to an array of primes of the denoted size. These 
            primes are located in the source file util/globals.cpp. Again, please keep 
            in mind that the choice of coeff_modulus has a dramatic effect on security 
            and should almost always be obtained through coeff_modulus_xxx(int).

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

                ~ log2(coeff_modulus/plain_modulus) (bits)

            and the noise budget consumption in a homomorphic multiplication is of the 
            form log2(plain_modulus) + (other terms).
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
            modulo plain_modulus. This is not a very practical object to encrypt: much
            more useful would be encrypting integers or floating point numbers. For this
            we need an `encoding scheme' to convert data from integer representation to
            an appropriate plaintext polynomial representation than can subsequently be 
            encrypted. SEAL comes with a few basic encoders for the BFV scheme:

            [IntegerEncoder]
            Given an integer base b, encodes integers as plaintext polynomials as follows. 
            First, a base-b expansion of the integer is computed. This expansion uses 
            a `balanced' set of representatives of integers modulo b as the coefficients. 
            Namely, when b is odd the coefficients are integers between -(b-1)/2 and 
            (b-1)/2. When b is even, the integers are between -b/2 and (b-1)/2, except 
            when b is two and the usual binary expansion is used (coefficients 0 and 1). 
            Decoding amounts to evaluating the polynomial at x=b. For example, if b=2, 
            the integer 

                26 = 2^4 + 2^3 + 2^1

            is encoded as the polynomial 1x^4 + 1x^3 + 1x^1. When b=3, 

                26 = 3^3 - 3^0 

            is encoded as the polynomial 1x^3 - 1. In memory polynomial coefficients are 
            always stored as unsigned integers by storing their smallest non-negative 
            representatives modulo plain_modulus. To create a base-b integer encoder, 
            use the constructor IntegerEncoder(plain_modulus, b). If no b is given, b=2 
            is used.

            [FractionalEncoder]
            The FractionalEncoder encodes fixed-precision rational numbers as follows. 
            It expands the number in a given base b, possibly truncating an infinite 
            fractional part to finite precision, e.g. 

                26.75 = 2^4 + 2^3 + 2^1 + 2^(-1) + 2^(-2) 

            when b=2. For the sake of the example, suppose poly_modulus is 1x^1024 + 1. 
            It then represents the integer part of the number in the same way as in 
            IntegerEncoder (with b=2 here), and moves the fractional part instead to the 
            highest degree part of the polynomial, but with signs of the coefficients 
            changed. In this example we would represent 26.75 as the polynomial 

                -1x^1023 - 1x^1022 + 1x^4 + 1x^3 + 1x^1. 

            In memory the negative coefficients of the polynomial will be represented as 
            their negatives modulo plain_modulus. While easy to use, the fractional
            encoder suffers from drawbacks that can be avoided using the CKKS scheme
            instead of BFV; hence, we do not demonstrate the FractionalEncoder in these
            examples.

            [BatchEncoder]
            If plain_modulus is a prime congruent to 1 modulo 2*poly_modulus_degree, the 
            plaintext elements can be viewed as 2-by-(poly_modulus_degree / 2) matrices
            with elements integers modulo plain_modulus. When a desired computation can 
            be vectorized, using BatchEncoder can result in a massive performance boost
            over naively encrypting and operating on each input number separately. Thus, 
            in more complicated computations this is likely to be by far the most 
            important and useful encoder. In example_bfv_basics_iii() we show how to
            operate on encrypted matrix plaintexts.

            Here we choose to create an IntegerEncoder with base b=2. For most use-cases
            of the IntegerEncoder this is a good choice.
            */
            IntegerEncoder encoder = new IntegerEncoder(parms.PlainModulus);

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
            print-out. The user can change the plain_modulus to see its effect on the
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

            There are actually two more types of keys in SEAL: `relinearization keys' 
            and `Galois keys'. In this example we will discuss relinearization keys, and 
            Galois keys will be discussed later in example_bfv_basics_iii().
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
            In SEAL, a valid ciphertext consists of two or more polynomials whose 
            coefficients are integers modulo the product of the primes in coeff_modulus. 
            The current size of a ciphertext can be found using Ciphertext::size().
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
            plain_modulus (0x400) and as a result we would no longer obtain the expected 
            result as an integer-coefficient polynomial. We can fix this problem to some 
            extent by increasing plain_modulus. This makes sense since we still have 
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
            be any integer at least 1 [dbc_min()] and at most 60 [dbc_max()]. A large
            decomposition bit count makes relinearization fast, but consumes more noise
            budget. A small decomposition bit count can make relinearization slower, but 
            might not change the noise budget by any observable amount.

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
            running time here, but relinearization with relin_keys60 (below) is much 
            faster than with relin_keys16.
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
            correct as integers: they have been reduced modulo plain_modulus, and there
            was no warning sign about this. It might be necessary to carefully analyze
            the computation to make sure such overflow does not occur unexpectedly.

            These experiments suggest that an optimal strategy might be to relinearize
            first with relinearization keys with a small decomposition bit count, and 
            later with relinearization keys with a larger decomposition bit count (for 
            performance) when noise budget has already been consumed past the bound 
            determined by the larger decomposition bit count. For example, the best 
            strategy might have been to use relin_keys16 in the first relinearization 
            and relin_keys60 in the next two relinearizations for optimal noise budget 
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
            like that of relinearization (recall example_bfv_basics_ii()).

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
            The total number of batching `slots' is poly_modulus_degree. The matrices 
            we encrypt are of size 2-by-(slot_count / 2).
            */
            ulong slotCount = batchEncoder.SlotCount;
            ulong rowSize = slotCount / 2;
            Console.WriteLine($"Plaintext matrix row size: {rowSize}");

            /*
            The matrix plaintext is simply given to BatchEncoder as a flattened vector
            of numbers of size slot_count. The first row_size numbers form the first row, 
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

            //            /*
            //            In this example we describe the concept of `parms_id' in the context of the
            //            BFV scheme and show how modulus switching can be used for improving both
            //            computation and communication cost.

            //            We start by setting up medium size parameters for BFV as usual.
            //            */
            //            EncryptionParameters parms(scheme_type::BFV);

            //            parms.set_poly_modulus_degree(8192);
            //            parms.set_coeff_modulus(coeff_modulus_128(8192));
            //            parms.set_plain_modulus(1 << 20);

            //            /*
            //            In SEAL a particular set of encryption parameters (excluding the random
            //            number generator) is identified uniquely by a SHA-3 hash of the parameters.
            //            This hash is called the `parms_id' and can be easily accessed and printed
            //            at any time. The hash will change as soon as any of the relevant parameters
            //            is changed.
            //            */
            //            cout << "Current parms_id: " << parms.parms_id() << endl;
            //            cout << "Changing plain_modulus ..." << endl;
            //            parms.set_plain_modulus((1 << 20) + 1);
            //            cout << "Current parms_id: " << parms.parms_id() << endl << endl;

            //            /*
            //            Create the context.
            //            */
            //            auto context = SEALContext::Create(parms);
            //            print_parameters(context);

            //            /*
            //            All keys and ciphertext, and in the CKKS also plaintexts, carry the parms_id
            //            for the encryption parameters they are created with, allowing SEAL to very 
            //            quickly determine whether the objects are valid for use and compatible for 
            //            homomorphic computations. SEAL takes care of managing, and verifying the 
            //            parms_id for all objects so the user should have no reason to change it by 
            //            hand. 
            //            */
            //            KeyGenerator keygen(context);
            //            auto public_key = keygen.public_key();
            //            auto secret_key = keygen.secret_key();
            //            cout << "parms_id of public_key: " << public_key.parms_id() << endl;
            //            cout << "parms_id of secret_key: " << secret_key.parms_id() << endl;

            //            Encryptor encryptor(context, public_key);
            //            Evaluator evaluator(context);
            //            Decryptor decryptor(context, secret_key);

            //            /*
            //            Note how in the BFV scheme plaintexts do not carry the parms_id, but 
            //            ciphertexts do.
            //            */
            //            Plaintext plain("1x^3 + 2x^2 + 3x^1 + 4");
            //            Ciphertext encrypted;
            //            encryptor.encrypt(plain, encrypted);
            //            cout << "parms_id of plain: " << plain.parms_id() << " (not set)" << endl;
            //            cout << "parms_id of encrypted: " << encrypted.parms_id() << endl << endl;

            //            /*
            //            When SEALContext is created from a given EncryptionParameters instance,
            //            SEAL automatically creates a so-called "modulus switching chain", which is
            //            a chain of other encryption parameters derived from the original set.
            //            The parameters in the modulus switching chain are the same as the original 
            //            parameters with the exception that size of the coefficient modulus is
            //            decreasing going down the chain. More precisely, each parameter set in the
            //            chain attempts to remove one of the coefficient modulus primes from the
            //            previous set; this continues until the parameter set is no longer valid
            //            (e.g. plain_modulus is larger than the remaining coeff_modulus). It is easy
            //            to walk through the chain and access all the parameter sets. Additionally,
            //            each parameter set in the chain has a `chain_index' that indicates its
            //            position in the chain so that the last set has index 0. We say that a set
            //            of encryption parameters, or an object carrying those encryption parameters,
            //            is at a higher level in the chain than another set of parameters if its the
            //            chain index is bigger, i.e. it is earlier in the chain. 
            //            */
            //            for (auto context_data = context->context_data(); context_data;
            //                context_data = context_data->next_context_data())
            //            {
            //                cout << "Chain index: " << context_data->chain_index() << endl;
            //                cout << "parms_id: " << context_data->parms().parms_id() << endl;
            //                cout << "coeff_modulus primes: ";
            //                cout << hex;
            //                for (const auto &prime : context_data->parms().coeff_modulus())
            //        {
            //                cout << prime.value() << " ";
            //            }
            //            cout << dec << endl;
            //            cout << "\\" << endl;
            //            cout << " \\-->" << endl;
            //        }
            //        cout << "End of chain reached" << endl << endl;

            //    /*
            //    Modulus switching changes the ciphertext parameters to any set down the
            //    chain from the current one. The function mod_switch_to_next(...) always
            //    switches to the next set down the chain, whereas mod_switch_to(...) switches
            //    to a parameter set down the chain corresponding to a given parms_id.
            //    */
            //    auto context_data = context->context_data();
            //    while(context_data->next_context_data()) 
            //    {
            //        cout << "Chain index: " << context_data->chain_index() << endl;
            //        cout << "parms_id of encrypted: " << encrypted.parms_id() << endl;
            //        cout << "Noise budget at this level: "
            //            << decryptor.invariant_noise_budget(encrypted) << " bits" << endl;
            //        cout << "\\" << endl;
            //        cout << " \\-->" << endl;
            //        evaluator.mod_switch_to_next_inplace(encrypted);
            //        context_data = context_data->next_context_data();
            //    }
            //    cout << "Chain index: " << context_data->chain_index() << endl;
            //    cout << "parms_id of encrypted: " << encrypted.parms_id() << endl;
            //    cout << "Noise budget at this level: "
            //        << decryptor.invariant_noise_budget(encrypted) << " bits" << endl;
            //    cout << "\\" << endl;
            //    cout << " \\-->" << endl;
            //    cout << "End of chain reached" << endl << endl;

            //    /*
            //    At this point it is hard to see any benefit in doing this: we lost a huge 
            //    amount of noise budget (i.e. computational power) at each switch and seemed
            //    to get nothing in return. The ciphertext still decrypts to the exact same
            //    value.
            //    */
            //    decryptor.decrypt(encrypted, plain);
            //    cout << "Decryption: " << plain.to_string() << endl << endl;

            //    /*
            //    However, there is a hidden benefit: the size of the ciphertext depends
            //    linearly on the number of primes in the coefficient modulus. Thus, if there 
            //    is no need or intention to perform any more computations on a given 
            //    ciphertext, we might as well switch it down to the smallest (last) set of 
            //    parameters in the chain before sending it back to the secret key holder for 
            //    decryption.

            //    Also the lost noise budget is actually not as issue at all, if we do things
            //    right, as we will see below. First we recreate the original ciphertext (with 
            //    largest parameters) and perform some simple computations on it.
            //    */
            //    encryptor.encrypt(plain, encrypted);
            //    auto relin_keys = keygen.relin_keys(60);
            //    cout << "Noise budget before squaring: "
            //        << decryptor.invariant_noise_budget(encrypted) << " bits" << endl;
            //    evaluator.square_inplace(encrypted);
            //    evaluator.relinearize_inplace(encrypted, relin_keys);
            //    cout << "Noise budget after squaring: "
            //        << decryptor.invariant_noise_budget(encrypted) << " bits" << endl;

            //    /*
            //    From the print-out we see that the noise budget after these computations is 
            //    just slightly below the level we would have in a fresh ciphertext after one 
            //    modulus switch (135 bits). Surprisingly, in this case modulus switching has 
            //    no effect at all on the modulus.
            //    */ 
            //    evaluator.mod_switch_to_next_inplace(encrypted);
            //    cout << "Noise budget after modulus switching: "
            //        << decryptor.invariant_noise_budget(encrypted) << " bits" << endl;

            //    /*
            //    This means that there is no harm at all in dropping some of the coefficient
            //    modulus after doing enough computations. In some cases one might want to
            //    switch to a lower level slightly earlier, actually sacrificing some of the 
            //    noise budget in the process, to gain computational performance from having
            //    a smaller coefficient modulus. We see from the print-out that that the next 
            //    modulus switch should be done ideally when the noise budget reaches 81 bits. 
            //    */
            //    evaluator.square_inplace(encrypted);
            //    evaluator.relinearize_inplace(encrypted, relin_keys);
            //    cout << "Noise budget after squaring: "
            //        << decryptor.invariant_noise_budget(encrypted) << " bits" << endl;
            //    evaluator.mod_switch_to_next_inplace(encrypted);
            //    cout << "Noise budget after modulus switching: "
            //        << decryptor.invariant_noise_budget(encrypted) << " bits" << endl;
            //    evaluator.square_inplace(encrypted);
            //    evaluator.relinearize_inplace(encrypted, relin_keys);
            //    cout << "Noise budget after squaring: "
            //        << decryptor.invariant_noise_budget(encrypted) << " bits" << endl;
            //    evaluator.mod_switch_to_next_inplace(encrypted);
            //    cout << "Noise budget after modulus switching: "
            //        << decryptor.invariant_noise_budget(encrypted) << " bits" << endl << endl;

            //    /*
            //    At this point the ciphertext still decrypts correctly, has very small size,
            //    and the computation was as efficient as possible. Note that the decryptor
            //    can be used to decrypt a ciphertext at any level in the modulus switching
            //    chain as long as the secret key is at a higher level in the same chain.
            //    */
            //    decryptor.decrypt(encrypted, plain);
            //    cout << "Decryption of eighth power: " << plain.to_string() << endl << endl;

            //    /*
            //    In BFV modulus switching is not necessary and in some cases the user might
            //    not want to create the modulus switching chain. This can be done by passing
            //    a bool `false' to the SEALContext::Create(...) function as follows.
            //    */
            //    context = SEALContext::Create(parms, false);

            //    /*
            //    We can check that indeed the modulus switching chain has not been created.
            //    The following loop should execute only once.
            //    */
            //    for (context_data = context->context_data(); context_data;
            //        context_data = context_data->next_context_data())
            //    {
            //        cout << "Chain index: " << context_data->chain_index() << endl;
            //        cout << "parms_id: " << context_data->parms().parms_id() << endl;
            //        cout << "coeff_modulus primes: ";
            //        cout << hex;
            //        for (const auto &prime : context_data->parms().coeff_modulus())
            //        {
            //            cout << prime.value() << " ";
            //        }
            //cout << dec << endl;
            //        cout << "\\" << endl;
            //        cout << " \\-->" << endl;
            //    }
            //    cout << "End of chain reached" << endl << endl;

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
                IntegerEncoder encoder = new IntegerEncoder(plainModulus);

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

                if (timeRotateColumnsSum.IsRunning)
                    throw new InvalidOperationException("Should not be running!!!!!");

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

                Console.WriteLine("Running tests ");
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
                    that multiply_plain does not change the size of the ciphertext so we 
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

        static void Main(string[] args)
        {
            while (true)
            {
                Console.WriteLine();
                Console.WriteLine("SEAL Examples:");
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
                        Console.WriteLine("6!");
                        break;

                    case ConsoleKey.D7:
                        Console.WriteLine("7!");
                        break;

                    case ConsoleKey.D8:
                        Console.WriteLine("8!");
                        break;

                    case ConsoleKey.D9:
                        Console.WriteLine("9!");
                        break;

                    case ConsoleKey.D0:
                        return;

                    default:
                        Console.WriteLine("Invalid option.");
                        break;
                }
            }
        }
    }
}
