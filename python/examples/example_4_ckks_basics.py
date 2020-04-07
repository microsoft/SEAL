import time
import random
from seal import EncryptionParameters, scheme_type, \
    SEALContext, print_parameters, KeyGenerator, \
    Encryptor, CoeffModulus, Evaluator, Decryptor, \
    Plaintext, Ciphertext, IntegerEncoder, PlainModulus, \
    BatchEncoder, CKKSEncoder, Int64Vector, UInt64Vector, \
    IntVector, DoubleVector
from numpy import log2
from example_2_encoders import print_vector


def example_ckks_basics():
    print("Example: CKKS Basics");

    #In this example we demonstrate evaluating a polynomial function
    #
    #    PI*x^3 + 0.4*x + 1
    #
    #on encrypted floating-point input data x for a set of 4096 equidistant points
    #in the interval [0, 1]. This example demonstrates many of the main features
    #of the CKKS scheme, but also the challenges in using it.
    #
    # We start by setting up the CKKS scheme.

    parms = EncryptionParameters(scheme_type.CKKS)

    #We saw in `2_encoders.cpp' that multiplication in CKKS causes scales
    #in ciphertexts to grow. The scale of any ciphertext must not get too close
    #to the total size of coeff_modulus, or else the ciphertext simply runs out of
    #room to store the scaled-up plaintext. The CKKS scheme provides a `rescale'
    #functionality that can reduce the scale, and stabilize the scale expansion.
    #
    #Rescaling is a kind of modulus switch operation (recall `3_levels.cpp').
    #As modulus switching, it removes the last of the primes from coeff_modulus,
    #but as a side-effect it scales down the ciphertext by the removed prime.
    #Usually we want to have perfect control over how the scales are changed,
    #which is why for the CKKS scheme it is more common to use carefully selected
    #primes for the coeff_modulus.
    #
    #More precisely, suppose that the scale in a CKKS ciphertext is S, and the
    #last prime in the current coeff_modulus (for the ciphertext) is P. Rescaling
    #to the next level changes the scale to S/P, and removes the prime P from the
    #coeff_modulus, as usual in modulus switching. The number of primes limits
    #how many rescalings can be done, and thus limits the multiplicative depth of
    #the computation.
    #
    #It is possible to choose the initial scale freely. One good strategy can be
    #to is to set the initial scale S and primes P_i in the coeff_modulus to be
    #very close to each other. If ciphertexts have scale S before multiplication,
    #they have scale S^2 after multiplication, and S^2/P_i after rescaling. If all
    #P_i are close to S, then S^2/P_i is close to S again. This way we stabilize the
    #scales to be close to S throughout the computation. Generally, for a circuit
    #of depth D, we need to rescale D times, i.e., we need to be able to remove D
    #primes from the coefficient modulus. Once we have only one prime left in the
    #coeff_modulus, the remaining prime must be larger than S by a few bits to
    #preserve the pre-decimal-point value of the plaintext.
    #
    #Therefore, a generally good strategy is to choose parameters for the CKKS
    #scheme as follows: 
    #
    #    (1) Choose a 60-bit prime as the first prime in coeff_modulus. This will
    #        give the highest precision when decrypting;
    #    (2) Choose another 60-bit prime as the last element of coeff_modulus, as
    #        this will be used as the special prime and should be as large as the
    #        largest of the other primes;
    #    (3) Choose the intermediate primes to be close to each other.
    #
    #We use CoeffModulus::Create to generate primes of the appropriate size. Note
    #that our coeff_modulus is 200 bits total, which is below the bound for our
    #poly_modulus_degree: CoeffModulus::MaxBitCount(8192) returns 218.

    poly_modulus_degree = 8192
    parms.set_poly_modulus_degree(poly_modulus_degree)
    parms.set_coeff_modulus(CoeffModulus.Create(
        poly_modulus_degree, IntVector([60, 40, 40, 60])))

    #We choose the initial scale to be 2^40. At the last level, this leaves us
    #60-40=20 bits of precision before the decimal point, and enough (roughly
    #10-20 bits) of precision after the decimal point. Since our intermediate
    #primes are 40 bits (in fact, they are very close to 2^40), we can achieve
    #scale stabilization as described above.

    scale = 2.0**40

    context = SEALContext.Create(parms)
    print_parameters(context)

    keygen = KeyGenerator(context)
    public_key = keygen.public_key()
    secret_key = keygen.secret_key()
    relin_keys = keygen.relin_keys()
    encryptor = Encryptor(context, public_key)
    evaluator = Evaluator(context)
    decryptor = Decryptor(context, secret_key)

    encoder = CKKSEncoder(context)
    slot_count = encoder.slot_count()
    print("Number of slots: {}".format(slot_count))

    step_size = 1.0 / (slot_count - 1)
    input = DoubleVector(list(map(lambda x: x*step_size, range(0, slot_count))))

    print("Input vector: ")
    print_vector(input)

    print("Evaluating polynomial PI*x^3 + 0.4x + 1 ...")

    #We create plaintexts for PI, 0.4, and 1 using an overload of CKKSEncoder::encode
    #that encodes the given floating-point value to every slot in the vector.

    plain_coeff3 = Plaintext()
    plain_coeff1 = Plaintext()
    plain_coeff0 = Plaintext()
    encoder.encode(3.14159265, scale, plain_coeff3)
    encoder.encode(0.4, scale, plain_coeff1)
    encoder.encode(1.0, scale, plain_coeff0)

    x_plain = Plaintext()
    print("Encode input vectors.")
    encoder.encode(input, scale, x_plain)
    x1_encrypted = Ciphertext() 
    encryptor.encrypt(x_plain, x1_encrypted)

    #To compute x^3 we first compute x^2 and relinearize. However, the scale has
    #now grown to 2^80.

    x3_encrypted = Ciphertext() 
    print("Compute x^2 and relinearize:")
    evaluator.square(x1_encrypted, x3_encrypted)
    evaluator.relinearize_inplace(x3_encrypted, relin_keys)
    print("    + Scale of x^2 before rescale: {} bits".format(log2(x3_encrypted.scale())))

    #Now rescale; in addition to a modulus switch, the scale is reduced down by
    #a factor equal to the prime that was switched away (40-bit prime). Hence, the
    #new scale should be close to 2^40. Note, however, that the scale is not equal
    #to 2^40: this is because the 40-bit prime is only close to 2^40.
    print("Rescale x^2.")
    evaluator.rescale_to_next_inplace(x3_encrypted)
    print("    + Scale of x^2 after rescale: {} bits".format(log2(x3_encrypted.scale())))

    #Now x3_encrypted is at a different level than x1_encrypted, which prevents us
    #from multiplying them to compute x^3. We could simply switch x1_encrypted to
    #the next parameters in the modulus switching chain. However, since we still
    #need to multiply the x^3 term with PI (plain_coeff3), we instead compute PI*x
    #first and multiply that with x^2 to obtain PI*x^3. To this end, we compute
    #PI*x and rescale it back from scale 2^80 to something close to 2^40.

    print("Compute and rescale PI*x.")
    x1_encrypted_coeff3 = Ciphertext() 
    evaluator.multiply_plain(x1_encrypted, plain_coeff3, x1_encrypted_coeff3)
    print("    + Scale of PI*x before rescale: {} bits".format(log2(x1_encrypted_coeff3.scale())))
    evaluator.rescale_to_next_inplace(x1_encrypted_coeff3)
    print("    + Scale of PI*x after rescale: {} bits".format(log2(x1_encrypted_coeff3.scale())))

    #Since x3_encrypted and x1_encrypted_coeff3 have the same exact scale and use
    #the same encryption parameters, we can multiply them together. We write the
    #result to x3_encrypted, relinearize, and rescale. Note that again the scale
    #is something close to 2^40, but not exactly 2^40 due to yet another scaling
    #by a prime. We are down to the last level in the modulus switching chain.

    print("Compute, relinearize, and rescale (PI*x)*x^2.")
    evaluator.multiply_inplace(x3_encrypted, x1_encrypted_coeff3)
    evaluator.relinearize_inplace(x3_encrypted, relin_keys)
    print("    + Scale of PI*x^3 before rescale: {} bits".format(log2(x3_encrypted.scale())))

    evaluator.rescale_to_next_inplace(x3_encrypted)
    print("    + Scale of PI*x^3 after rescale: {} bits".format(log2(x3_encrypted.scale())))

    #Next we compute the degree one term. All this requires is one multiply_plain
    #with plain_coeff1. We overwrite x1_encrypted with the result.

    print("Compute and rescale 0.4*x.")
    evaluator.multiply_plain_inplace(x1_encrypted, plain_coeff1)
    print("    + Scale of 0.4*x before rescale: {} bits".format(log2(x1_encrypted.scale())))
    evaluator.rescale_to_next_inplace(x1_encrypted)
    print("    + Scale of 0.4*x after rescale: {} bits".format(log2(x1_encrypted.scale())))

    #Now we would hope to compute the sum of all three terms. However, there is
    #a serious problem: the encryption parameters used by all three terms are
    #different due to modulus switching from rescaling.
    #
    #Encrypted addition and subtraction require that the scales of the inputs are
    #the same, and also that the encryption parameters (parms_id) match. If there
    #is a mismatch, Evaluator will throw an exception.

    print("Parameters used by all three terms are different.")
    print("    + Modulus chain index for x3_encrypted: {}".format(
        context.get_context_data(x3_encrypted.parms_id()).chain_index()))
    print("    + Modulus chain index for x1_encrypted: {}".format(
        context.get_context_data(x1_encrypted.parms_id()).chain_index()))
    print("    + Modulus chain index for plain_coeff0: {}".format(
        context.get_context_data(plain_coeff0.parms_id()).chain_index()))

    #Let us carefully consider what the scales are at this point. We denote the
    #primes in coeff_modulus as P_0, P_1, P_2, P_3, in this order. P_3 is used as
    #the special modulus and is not involved in rescalings. After the computations
    #above the scales in ciphertexts are:
    #
    #    - Product x^2 has scale 2^80 and is at level 2;
    #    - Product PI*x has scale 2^80 and is at level 2;
    #    - We rescaled both down to scale 2^80/P_2 and level 1;
    #    - Product PI*x^3 has scale (2^80/P_2)^2;
    #    - We rescaled it down to scale (2^80/P_2)^2/P_1 and level 0;
    #    - Product 0.4*x has scale 2^80;
    #    - We rescaled it down to scale 2^80/P_2 and level 1;
    #    - The contant term 1 has scale 2^40 and is at level 2.
    #
    #Although the scales of all three terms are approximately 2^40, their exact
    #values are different, hence they cannot be added together.

    print("The exact scales of all three terms are different:")
    print("    + Exact scale in PI*x^3: {0:0.10f}".format(x3_encrypted.scale()))
    print("    + Exact scale in  0.4*x: {0:0.10f}".format(x1_encrypted.scale()))
    print("    + Exact scale in      1: {0:0.10f}".format(plain_coeff0.scale()))

    #There are many ways to fix this problem. Since P_2 and P_1 are really close
    #to 2^40, we can simply "lie" to Microsoft SEAL and set the scales to be the
    #same. For example, changing the scale of PI*x^3 to 2^40 simply means that we
    #scale the value of PI*x^3 by 2^120/(P_2^2*P_1), which is very close to 1.
    #This should not result in any noticeable error.
    #
    #Another option would be to encode 1 with scale 2^80/P_2, do a multiply_plain
    #with 0.4*x, and finally rescale. In this case we would need to additionally
    #make sure to encode 1 with appropriate encryption parameters (parms_id).
    #
    #In this example we will use the first (simplest) approach and simply change
    #the scale of PI*x^3 and 0.4*x to 2^40.
    print("Normalize scales to 2^40.")
    x3_encrypted.set_scale(2.0**40)
    x1_encrypted.set_scale(2.0**40)

    #We still have a problem with mismatching encryption parameters. This is easy
    #to fix by using traditional modulus switching (no rescaling). CKKS supports
    #modulus switching just like the BFV scheme, allowing us to switch away parts
    #of the coefficient modulus when it is simply not needed.

    print("Normalize encryption parameters to the lowest level.")
    last_parms_id = x3_encrypted.parms_id()
    evaluator.mod_switch_to_inplace(x1_encrypted, last_parms_id)
    evaluator.mod_switch_to_inplace(plain_coeff0, last_parms_id)

    #All three ciphertexts are now compatible and can be added.

    print("Compute PI*x^3 + 0.4*x + 1.")
    encrypted_result = Ciphertext()
    evaluator.add(x3_encrypted, x1_encrypted, encrypted_result)
    evaluator.add_plain_inplace(encrypted_result, plain_coeff0)

    #First print the true result.

    plain_result = Plaintext() 
    print("Decrypt and decode PI*x^3 + 0.4x + 1.")
    print("    + Expected result:")
    true_result = DoubleVector(list(map(lambda x: (3.14159265 * x * x + 0.4)* x + 1, input)))
    print_vector(true_result)

    #Decrypt, decode, and print the result.
    decryptor.decrypt(encrypted_result, plain_result)
    result = DoubleVector()
    encoder.decode(plain_result, result)
    print("    + Computed result ...... Correct.")
    print_vector(result)

    #While we did not show any computations on complex numbers in these examples,
    #the CKKSEncoder would allow us to have done that just as easily. Additions
    #and multiplications of complex numbers behave just as one would expect.

if __name__ == '__main__':
    example_ckks_basics()
