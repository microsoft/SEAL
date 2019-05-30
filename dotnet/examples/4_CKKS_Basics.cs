// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

using System;
using System.Collections.Generic;
using System.Text;

namespace SEALNetExamples
{
    partial class Examples
    {
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

    }
}
