from seal import EncryptionParameters, scheme_type, \
    SEALContext, print_parameters, KeyGenerator, \
    Encryptor, CoeffModulus, Evaluator, Decryptor, \
    Plaintext, Ciphertext, IntegerEncoder, PlainModulus, \
    BatchEncoder, CKKSEncoder, Int64Vector, UInt64Vector, \
    IntVector, DoubleVector, CiphertextVector, GaloisKeys, \
    RelinKeys
import numpy as np
import itertools


def diag_repr(U:np.ndarray, i:int) -> np.ndarray:
    N, M = U.shape
    if (N!=M):
        raise Exception("diag_repr only works for square matrices")
    else:
        result = np.concatenate([np.diag(U,i), np.diag(U, -N+i)])
        if len(result) != N:
            raise Exception("diag_repr index is out of bounds")
        return result 
        

def lin_trans(U:np.ndarray, ct: Ciphertext, evaluator:Evaluator, encoder:CKKSEncoder,
              gal_keys:GaloisKeys, relin_keys:RelinKeys=None) -> Ciphertext:
    """
    From page 5 at https://eprint.iacr.org/2018/1041.pdf

    NOTE: We denote homomorphic multiplication and constant multiplication by Mult and CMult
    
    In general, an arbitrary linear transformation L: Rn -> Rn over plaintext vectors can be 
    represented as L:m -> U·m for some matrix U \in Rn×n. We can express the matrix-vector 
    multiplication by combining rotation and constant multiplication operations. Specifically,
    for 0<=l< n, we define the l-th diagonal vector of U by 

    ul= (U_{0,l} , U_{1,l+1}, ..., U_{n−l−1,n−1} ,U_{n−l,0}, ..., U_{n−1,l−1} ) \in Rn. 
evaluator.multiply_plain(ct
    ul = (U__{k, (l+k) mod n}), k=0,...,n-1

    Then we have 
    
    U \dot m= \sum_{0<=l<n} (u_l . ρ(m;l))

    where . denotes the component-wise multiplication between vectors. 
    Given a matrix U \in Rn×n and an encryptionct of the vector m, the following algorithm 
    describes how to compute a ciphertext of the desired vector U \dot m.

    ############# Algorithm #############
    procedure LinTrans(ct;U)
    1: ct_ <- CMult(ct;u0)
    2: for l = 1 to n−1 do
    3:   ct_ <- Add(ct_,CMult(Rot(ct;l); ul))
    4: end for
    5: return ct_
    #####################################
    """
    M, N = U.shape
    if (N!=M):
        raise Exception("lin_trans only works for square matrices")
    scale = ct.scale()
    parms_id = ct.parms_id()
    acc = CiphertextVector() 
    for l in range(N):
        ul_vec_np = diag_repr(U,l)
        if np.abs(ul_vec_np).sum() == 0:
            continue
        ul_vec = DoubleVector(ul_vec_np.tolist())
        ul = Plaintext()
        encoder.encode(ul_vec, scale, ul)
        #Encrypted addition and subtraction require that the scales of the inputs are
        #the same, and also that the encryption parameters (parms_id) match. If there
        #is a mismatch, Evaluator will throw an exception.
        #Here we make sure to encode ul with appropriate encryption parameters (parms_id).
        evaluator.mod_switch_to_inplace(ul, parms_id)
        ct_l = Ciphertext()
        evaluator.rotate_vector(ct, l, gal_keys, ct_l)
        evaluator.multiply_plain_inplace(ct_l, ul)
        acc.append(ct_l)
    out = Ciphertext()
    evaluator.add_many(acc, out)
    if not (relin_keys is None):
        evaluator.relinearize_inplace(out, relin_keys)
        evaluator.rescale_to_next_inplace(out)
    return out 


def sigma_permutation(d, nmax):
    n = d*d
    Usigma = np.zeros(n*n).reshape(n,n)
    for i, j in itertools.product(range(d), range(d)):
        Usigma[d*i+j, d*i+((i+j) % d)] = 1.0
    output = np.kron(np.eye(2), Usigma)
    return output[0:nmax,0:nmax]

def tau_permutation(d, nmax):
    n = d*d
    Utau = np.zeros(n*n).reshape(n,n)
    for i, j in itertools.product(range(d), range(d)):
        Utau[d*i+j, d*((i+j) % d)+j] = 1.0
    output = np.kron(np.eye(2), Utau)
    return output[0:nmax, 0:nmax]

def phi_permutation_k(k, d, nmax):
    n = d*d
    Vk = np.zeros(n*n).reshape(n,n)
    for i, j in itertools.product(range(d), range(d)):
        Vk[d*i+j, d*i+((j+k) % d)] = 1.0
    return Vk
    
def psi_permutation_k(k, d, nmax):
    n = d*d
    Wk = np.zeros(n*n).reshape(n,n)
    for i, j in itertools.product(range(d), range(d)):
        Wk[d*i+j, d*((i+k) % d)+j] = 1.0
    return Wk

def cA_x_cB(A:Ciphertext, B:Ciphertext, evaluator:Evaluator, relin_keys:RelinKeys):
    """
    Element-wise product of cipherthextA and ciphertextB
    """
    C = Ciphertext()
    evaluator.multiply(A, B, C)
    evaluator.relinearize_inplace(C, relin_keys)
    evaluator.rescale_to_next_inplace(C)
    return C

def cA_dot_cB(ct_A:Ciphertext, ct_B:Ciphertext, evaluator:Evaluator, encoder:CKKSEncoder,
                gal_keys:GaloisKeys, relin_keys:RelinKeys, d:int) -> Ciphertext:
    """
    Inspired by "Secure Outsourced Matrix Computationand Application to Neural Networks?"
    Link: https://eprint.iacr.org/2018/1041.pdf
    """
    nmax = encoder.slot_count()
    n = d*d
    if n > nmax/2:
       raise("Matrix dimenson is higher than the one suported by the encoder")
    Usigma = sigma_permutation(d, nmax)
    Utau = tau_permutation(d, nmax) 
    ct_A0 = lin_trans(Usigma, ct_A, evaluator, encoder, gal_keys, relin_keys)
    ct_B0 = lin_trans(Utau, ct_B, evaluator, encoder, gal_keys, relin_keys)
    ct_Ak = CiphertextVector()
    ct_Bk = CiphertextVector()
    for k in range(1, d):
        Vk = phi_permutation_k(k, d, nmax)
        Wk = psi_permutation_k(k, d, nmax)
        if Vk.sum() == 0 or Wk.sum() == 0:
            continue

        ct_Ak.append(lin_trans(Vk, ct_A0, evaluator, encoder, gal_keys, relin_keys))
        ct_Bk.append(lin_trans(Wk, ct_B0, evaluator, encoder, gal_keys, relin_keys))

    ct_AB = cA_x_cB(ct_A0, ct_B0, evaluator, relin_keys)
    for k in range(len(ct_Ak)):
        ct_ABk = cA_x_cB(ct_Ak[k], ct_Bk[k], evaluator, relin_keys)
        parms_id = ct_ABk.parms_id()
        evaluator.mod_switch_to_inplace(ct_AB, parms_id)
        ct_ABk.set_scale(ct_AB.scale())
        evaluator.add_inplace(ct_AB, ct_ABk)
    return ct_AB


def encrypt_array(matrix:np.ndarray, encryptor:Encryptor, encoder:CKKSEncoder, scale:float) -> Ciphertext:
    M, N = matrix.shape
    Nmax = encoder.slot_count()
    plain = Plaintext()
    cmatrix = Ciphertext() 
    encoder.encode(DoubleVector((matrix.flatten().tolist())*int(Nmax/N/M)), scale, plain)
    encryptor.encrypt(plain, cmatrix)
    return cmatrix
 

def decrypt_array(cipher:Ciphertext, decryptor:Decryptor, encoder:CKKSEncoder, M:int, N:int) -> np.ndarray:
    plain = Plaintext()
    decryptor.decrypt(cipher, plain)
    vec = DoubleVector()
    encoder.decode(plain, vec)
    matrix = np.array(vec[0:(M*N)]).reshape(M,N)
    return matrix 


def example_plain_square_matrix_cipher_vector_multiplication():
    parms = EncryptionParameters(scheme_type.CKKS)

    poly_modulus_degree = 8192
    parms.set_poly_modulus_degree(poly_modulus_degree)
    parms.set_coeff_modulus(CoeffModulus.Create(
        poly_modulus_degree, IntVector([40, 40, 40, 40])))

    context = SEALContext.Create(parms)
    print_parameters(context)

    keygen = KeyGenerator(context)
    public_key = keygen.public_key()
    secret_key = keygen.secret_key()
    relin_keys = keygen.relin_keys()
    gal_keys = keygen.galois_keys()
    encryptor = Encryptor(context, public_key)
    evaluator = Evaluator(context)
    decryptor = Decryptor(context, secret_key)

    ckks_encoder = CKKSEncoder(context)

    Nmax = ckks_encoder.slot_count()
    #N = int(Nmax**0.5)
    N = 8
    scale = 2.0**40

    #square matrix of size N
    #U = np.arange(1.0*(N*N)).reshape(N,N)
    #U = np.eye(N)
    U = np.zeros(N*N).reshape(N,N)
    U[0,1] = 1.0
    U[0,3] = 1.0
    U[0,5] = 1.0
    U[0,7] = 1.0

    # vector of size N
    m = np.arange(1.0*N).reshape(N,1)
    cm = encrypt_array(m, encryptor, ckks_encoder, scale)
    Um = U.dot(m)

    Um_enc = lin_trans(U, cm, evaluator, ckks_encoder, gal_keys, relin_keys)
    Um_dec = decrypt_array(Um_enc, decryptor, ckks_encoder, N, 1)

    print("Max absolute difference between real and Decrypted: {}".format(np.max(np.abs(Um_dec - Um) )))

       
def example_cipher_square_matrices_multiplication():
    """
    Inspired by "Secure Outsourced Matrix Computationand Application to Neural Networks?"
    Link: https://eprint.iacr.org/2018/1041.pdf
    """
    parms = EncryptionParameters(scheme_type.CKKS)

    poly_modulus_degree = 16384
    parms.set_poly_modulus_degree(poly_modulus_degree)
    parms.set_coeff_modulus(CoeffModulus.Create(
        poly_modulus_degree, IntVector([60, 40, 40, 40, 40, 40, 60])))

    context = SEALContext.Create(parms)
    print_parameters(context)

    keygen = KeyGenerator(context)
    public_key = keygen.public_key()
    secret_key = keygen.secret_key()
    relin_keys = keygen.relin_keys()
    gal_keys = keygen.galois_keys()
    encryptor = Encryptor(context, public_key)
    evaluator = Evaluator(context)
    decryptor = Decryptor(context, secret_key)

    ckks_encoder = CKKSEncoder(context)
    Nmax = ckks_encoder.slot_count()

    N = 16 
    scale = 2.0**40
        
    A = np.eye(N)
    B = np.arange(1.0*(N*N)).reshape(N,N)/N/N
    C = A.dot(B)
    
    A_enc = encrypt_array(A, encryptor, ckks_encoder, scale)
    B_enc = encrypt_array(B, encryptor, ckks_encoder, scale)
    C_enc = cA_dot_cB(A_enc, B_enc, evaluator, ckks_encoder, gal_keys, relin_keys, N)
    C_dec = decrypt_array(C_enc, decryptor, ckks_encoder, N, N)

    print("Max absolute difference between real and Decrypted: {}".format(np.max(np.abs(C_dec - C))))
    
