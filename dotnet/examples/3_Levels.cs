// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

using System;
using System.Collections.Generic;
using System.Text;

namespace SEALNetExamples
{
    partial class Examples
    {
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
            Create the context.
            */
            SEALContext context = SEALContext.Create(parms);
            Utilities.PrintParameters(context);

            /*
            In Microsoft SEAL a particular set of encryption parameters (excluding the
            random number generator) is identified uniquely by a SHA-3 hash of the
            parameters. This hash is called the `ParmsId' and can be easily accessed and
            printed at any time. The hash will change as soon as any of the relevant
            parameters is changed.
            */

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
            no effect at all on the noise budget.
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
    }
}
