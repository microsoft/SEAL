using Microsoft.Research.SEAL;
using System;
using System.Collections;
using System.Collections.Generic;

namespace SEALNetExamples
{
    class Examples
    {
        static void Main(string[] args)
        {
            while (true)
            {
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

                ConsoleKeyInfo key;
                do
                {
                    key = Console.ReadKey();
                } while (key.KeyChar < '0' || key.KeyChar > '9');
                Console.WriteLine();

                switch(key.Key)
                {
                    case ConsoleKey.D1:
                        ExampleBFVBasicsI();
                        break;

                    case ConsoleKey.D2:
                        Console.WriteLine("2!");
                        break;

                    case ConsoleKey.D3:
                        Console.WriteLine("3!");
                        break;

                    case ConsoleKey.D4:
                        Console.WriteLine("4!");
                        break;

                    case ConsoleKey.D5:
                        Console.WriteLine("5!");
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
    }
}
