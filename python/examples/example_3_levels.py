import time
import random
from seal import EncryptionParameters, scheme_type, \
    SEALContext, print_parameters, KeyGenerator, \
    Encryptor, CoeffModulus, Evaluator, Decryptor, \
    Plaintext, Ciphertext, IntegerEncoder, PlainModulus, \
    BatchEncoder, CKKSEncoder, Int64Vector, UInt64Vector, \
    IntVector, DoubleVector


def list2hex(lst):
    return list(map(lambda x: hex(x), lst)) 


def example_levels():
    print("Example: Levels")

    #In this examples we describe the concept of `levels' in BFV and CKKS and the
    #related objects that represent them in Microsoft SEAL.
    #
    #In Microsoft SEAL a set of encryption parameters (excluding the random number
    #generator) is identified uniquely by a 256-bit hash of the parameters. This
    #hash is called the `parms_id' and can be easily accessed and printed at any
    #time. The hash will change as soon as any of the parameters is changed.
    #
    #When a SEALContext is created from a given EncryptionParameters instance,
    #Microsoft SEAL automatically creates a so-called `modulus switching chain',
    #which is a chain of other encryption parameters derived from the original set.
    #The parameters in the modulus switching chain are the same as the original
    #parameters with the exception that size of the coefficient modulus is
    #decreasing going down the chain. More precisely, each parameter set in the
    #chain attempts to remove the last coefficient modulus prime from the
    #previous set; this continues until the parameter set is no longer valid
    #(e.g., plain_modulus is larger than the remaining coeff_modulus). It is easy
    #to walk through the chain and access all the parameter sets. Additionally,
    #each parameter set in the chain has a `chain index' that indicates its
    #position in the chain so that the last set has index 0. We say that a set
    #of encryption parameters, or an object carrying those encryption parameters,
    #is at a higher level in the chain than another set of parameters if its the
    #chain index is bigger, i.e., it is earlier in the chain.
    #
    #Each set of parameters in the chain involves unique pre-computations performed
    #when the SEALContext is created, and stored in a SEALContext::ContextData
    #object. The chain is basically a linked list of SEALContext::ContextData
    #objects, and can easily be accessed through the SEALContext at any time. Each
    #node can be identified by the parms_id of its specific encryption parameters
    #(poly_modulus_degree remains the same but coeff_modulus varies).

    parms = EncryptionParameters(scheme_type.BFV)

    poly_modulus_degree = 8192
    parms.set_poly_modulus_degree(poly_modulus_degree)

    #In this example we use a custom coeff_modulus, consisting of 5 primes of
    #sizes 50, 30, 30, 50, and 50 bits. Note that this is still OK according to
    #the explanation in `1_bfv_basics.cpp'. Indeed,
    #
    #    CoeffModulus::MaxBitCount(poly_modulus_degree)
    #
    #returns 218 (greater than 50+30+30+50+50=210).
    #
    #Due to the modulus switching chain, the order of the 5 primes is significant.
    #The last prime has a special meaning and we call it the `special prime'. Thus,
    #the first parameter set in the modulus switching chain is the only one that
    #involves the special prime. All key objects, such as SecretKey, are created
    #at this highest level. All data objects, such as Ciphertext, can be only at
    #lower levels. The special prime should be as large as the largest of the
    #other primes in the coeff_modulus, although this is not a strict requirement.
    #
    #          special prime +---------+
    #                                  |
    #                                  v
    #coeff_modulus: { 50, 30, 30, 50, 50 }  +---+  Level 4 (all keys; `key level')
    #                                           |
    #                                           |
    #    coeff_modulus: { 50, 30, 30, 50 }  +---+  Level 3 (highest `data level')
    #                                           |
    #                                           |
    #        coeff_modulus: { 50, 30, 30 }  +---+  Level 2
    #                                           |
    #                                           |
    #            coeff_modulus: { 50, 30 }  +---+  Level 1
    #                                           |
    #                                           |
    #                coeff_modulus: { 50 }  +---+  Level 0 (lowest level)

    parms.set_coeff_modulus(CoeffModulus.Create(
        poly_modulus_degree, IntVector([50, 30, 30, 50, 50])))

    #In this example the plain_modulus does not play much of a role; we choose
    #some reasonable value.

    parms.set_plain_modulus(PlainModulus.Batching(poly_modulus_degree, 20))

    context = SEALContext.Create(parms)
    print_parameters(context)

    #There are convenience method for accessing the SEALContext::ContextData for
    #some of the most important levels:
    #
    #    SEALContext::key_context_data(): access to key level ContextData
    #    SEALContext::first_context_data(): access to highest data level ContextData
    #    SEALContext::last_context_data(): access to lowest level ContextData
    #
    #We iterate over the chain and print the parms_id for each set of parameters.

    print("Print the modulus switching chain.")

    #First print the key level parameter information.

    context_data = context.key_context_data()
    print("----> Level (chain index): {} ...... key_context_data()".format(context_data.chain_index()))
    print("      parms_id: {}".format(list2hex(context_data.parms_id())))
    print("coeff_modulus primes:", end=' ')
    for prime in context_data.parms().coeff_modulus():
        print(hex(prime.value()), end=' ')
    print("")
    print("\\")
    print(" \\-->")

    #Next iterate over the remaining (data) levels.

    context_data = context.first_context_data()
    while (context_data):
        print(" Level (chain index): {} ".format(context_data.chain_index()), end='')
        if context_data.parms_id() == context.first_parms_id():
            print(" ...... first_context_data()")
        elif context_data.parms_id() == context.last_parms_id():
            print(" ...... last_context_data()")
        else:
            print("")
        print("      parms_id: {}".format(list2hex(context_data.parms_id())))
        print("coeff_modulus primes:", end=' ')
        for prime in context_data.parms().coeff_modulus():
            print(hex(prime.value()), end=' ')
        print("")
        print("\\")
        print(" \\-->")

        #Step forward in the chain.
        context_data = context_data.next_context_data()

    print(" End of chain reached")

    #We create some keys and check that indeed they appear at the highest level.

    keygen = KeyGenerator(context)
    public_key = keygen.public_key()
    secret_key = keygen.secret_key()
    relin_keys = keygen.relin_keys()
    galois_keys = keygen.galois_keys()
    print("Print the parameter IDs of generated elements.")
    print("    + public_key:  {}".format(list2hex(public_key.parms_id())))
    print("    + secret_key:  {}".format(list2hex(secret_key.parms_id())))
    print("    + relin_keys:  {}".format(list2hex(relin_keys.parms_id())))
    print("    + galois_keys: {}".format(list2hex(galois_keys.parms_id())))

    encryptor = Encryptor(context, public_key)
    evaluator = Evaluator(context)
    decryptor = Decryptor(context, secret_key)

    #In the BFV scheme plaintexts do not carry a parms_id, but ciphertexts do. Note
    #how the freshly encrypted ciphertext is at the highest data level.

    plain = Plaintext("1x^3 + 2x^2 + 3x^1 + 4")
    encrypted = Ciphertext()  
    encryptor.encrypt(plain, encrypted);
    print("    + plain:       {} (not set in BFV)".format(list2hex(plain.parms_id())))
    print("    + encrypted:   {}".format(list2hex(encrypted.parms_id())))

    #`Modulus switching' is a technique of changing the ciphertext parameters down
    #in the chain. The function Evaluator::mod_switch_to_next always switches to
    #the next level down the chain, whereas Evaluator::mod_switch_to switches to
    #a parameter set down the chain corresponding to a given parms_id. However, it
    #is impossible to switch up in the chain.

    print("Perform modulus switching on encrypted and print.")
    context_data = context.first_context_data()
    print("---->")

    while(context_data.next_context_data()):
        print(" Level (chain index): {} ".format(context_data.chain_index()))
        print("      parms_id of encrypted: {}".format(list2hex(encrypted.parms_id())))
        print("      Noise budget at this level: {} bits".format(
            decryptor.invariant_noise_budget(encrypted)))
        print("\\")
        print(" \\-->")
        evaluator.mod_switch_to_next_inplace(encrypted)
        context_data = context_data.next_context_data()

    print(" Level (chain index): {}".format(context_data.chain_index()))
    print("      parms_id of encrypted: {}".format(encrypted.parms_id()))
    print("      Noise budget at this level: {} bits".format(
        decryptor.invariant_noise_budget(encrypted))) 
    print("\\")
    print(" \\-->")
    print(" End of chain reached")

    #At this point it is hard to see any benefit in doing this: we lost a huge
    #amount of noise budget (i.e., computational power) at each switch and seemed
    #to get nothing in return. Decryption still works.

    print("Decrypt still works after modulus switching.")
    decryptor.decrypt(encrypted, plain)
    print("    + Decryption of encrypted: {} ...... Correct.".format(plain.to_string()))

    #However, there is a hidden benefit: the size of the ciphertext depends
    #linearly on the number of primes in the coefficient modulus. Thus, if there
    #is no need or intention to perform any further computations on a given
    #ciphertext, we might as well switch it down to the smallest (last) set of
    #parameters in the chain before sending it back to the secret key holder for
    #decryption.
    #
    #Also the lost noise budget is actually not an issue at all, if we do things
    #right, as we will see below.
    #
    #First we recreate the original ciphertext and perform some computations.

    print("Computation is more efficient with modulus switching.")
    print("Compute the 8th power.")
    encryptor.encrypt(plain, encrypted)
    print("    + Noise budget fresh:                   {} bits".format(
        decryptor.invariant_noise_budget(encrypted)))
    evaluator.square_inplace(encrypted)
    evaluator.relinearize_inplace(encrypted, relin_keys)
    print("    + Noise budget of the 2nd power:         {} bits".format(
        decryptor.invariant_noise_budget(encrypted)))
    evaluator.square_inplace(encrypted)
    evaluator.relinearize_inplace(encrypted, relin_keys)
    print("    + Noise budget of the 4th power:         {} bits".format(
        decryptor.invariant_noise_budget(encrypted)))

    #Surprisingly, in this case modulus switching has no effect at all on the
    #noise budget.

    evaluator.mod_switch_to_next_inplace(encrypted)
    print("    + Noise budget after modulus switching:  {} bits".format(
        decryptor.invariant_noise_budget(encrypted)))

    #This means that there is no harm at all in dropping some of the coefficient
    #modulus after doing enough computations. In some cases one might want to
    #switch to a lower level slightly earlier, actually sacrificing some of the
    #noise budget in the process, to gain computational performance from having
    #smaller parameters. We see from the print-out that the next modulus switch
    #should be done ideally when the noise budget is down to around 25 bits.

    evaluator.square_inplace(encrypted)
    evaluator.relinearize_inplace(encrypted, relin_keys)
    print("    + Noise budget of the 8th power:         {} bits".format(
        decryptor.invariant_noise_budget(encrypted)))
    evaluator.mod_switch_to_next_inplace(encrypted)
    print("    + Noise budget after modulus switching:  {} bits".format(
        decryptor.invariant_noise_budget(encrypted)))

    #At this point the ciphertext still decrypts correctly, has very small size,
    #and the computation was as efficient as possible. Note that the decryptor
    #can be used to decrypt a ciphertext at any level in the modulus switching
    #chain.

    decryptor.decrypt(encrypted, plain)
    print("    + Decryption of the 8th power (hexadecimal) ...... Correct.")
    print("    {}".format(plain.to_string()))

    #In BFV modulus switching is not necessary and in some cases the user might
    #not want to create the modulus switching chain, except for the highest two
    #levels. This can be done by passing a bool `false' to SEALContext::Create.

    context = SEALContext.Create(parms, False)

    #We can check that indeed the modulus switching chain has been created only
    #for the highest two levels (key level and highest data level). The following
    #loop should execute only once.

    print("Optionally disable modulus switching chain expansion.")
    print("Print the modulus switching chain.")
    print("---->")

    context_data = context.key_context_data()
    while (context_data):
        print(" Level (chain index): {}".format(context_data.chain_index()))
        print("      parms_id: {}".format(list2hex(context_data.parms_id())))
        print("coeff_modulus primes:", end=' ')
        for prime in context_data.parms().coeff_modulus():
            print(hex(prime.value()), end=' ')
        print("")
        print("\\")
        print(" \\-->")
        context_data = context_data.next_context_data()

    print(" End of chain reached")

    #It is very important to understand how this example works since in the CKKS
    #scheme modulus switching has a much more fundamental purpose and the next
    #examples will be difficult to understand unless these basic properties are
    #totally clear.


if __name__ == '__main__':
    example_levels()
