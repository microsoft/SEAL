#include <pybind11/pybind11.h>
#include <pybind11/stl_bind.h>
#include <pybind11/stl.h>
#include "seal/util/defines.h"
#include "seal/biguint.h"
#include "seal/ciphertext.h"
#include "seal/ckks.h"
#include "seal/modulus.h"
#include "seal/context.h"
#include "seal/decryptor.h"
#include "seal/intencoder.h"
#include "seal/util/defines.h"
#include "seal/encryptionparams.h"
#include "seal/encryptor.h"
#include "seal/evaluator.h"
#include "seal/intarray.h"
#include "seal/keygenerator.h"
#include "seal/memorymanager.h"
#include "seal/plaintext.h"
#include "seal/batchencoder.h"
#include "seal/publickey.h"
#include "seal/randomgen.h"        
#include "seal/randomtostd.h"
#include "seal/relinkeys.h"
#include "seal/secretkey.h"
#include "seal/serialization.h"
#include "seal/smallmodulus.h"
#include "seal/valcheck.h"

namespace py = pybind11;

using namespace pybind11::literals;
using namespace seal;
using namespace std;

PYBIND11_MAKE_OPAQUE(std::vector<int>);
PYBIND11_MAKE_OPAQUE(std::vector<uint32_t>);
PYBIND11_MAKE_OPAQUE(std::vector<int64_t>);
PYBIND11_MAKE_OPAQUE(std::vector<uint64_t>);
PYBIND11_MAKE_OPAQUE(std::vector<double>);
PYBIND11_MAKE_OPAQUE(std::vector<std::complex<double>>);

/*
Helper function: Prints the parameters in a SEALContext.
*/
void print_parameters(std::shared_ptr<seal::SEALContext> context)
{
    // Verify parameters
    if (!context)
    {
        throw std::invalid_argument("context is not set");
    }
    auto &context_data = *context->key_context_data();

    /*
    Which scheme are we using?
    */
    std::string scheme_name;
    switch (context_data.parms().scheme())
    {
    case seal::scheme_type::BFV:
        scheme_name = "BFV";
        break;
    case seal::scheme_type::CKKS:
        scheme_name = "CKKS";
        break;
    default:
        throw std::invalid_argument("unsupported scheme");
    }
    std::cout << "/" << std::endl;
    std::cout << "| Encryption parameters :" << std::endl;
    std::cout << "|   scheme: " << scheme_name << std::endl;
    std::cout << "|   poly_modulus_degree: " <<
        context_data.parms().poly_modulus_degree() << std::endl;

    /*
    Print the size of the true (product) coefficient modulus.
    */
    std::cout << "|   coeff_modulus size: ";
    std::cout << context_data.total_coeff_modulus_bit_count() << " (";
    auto coeff_modulus = context_data.parms().coeff_modulus();
    std::size_t coeff_mod_count = coeff_modulus.size();
    for (std::size_t i = 0; i < coeff_mod_count - 1; i++)
    {
        std::cout << coeff_modulus[i].bit_count() << " + ";
    }
    std::cout << coeff_modulus.back().bit_count();
    std::cout << ") bits" << std::endl;

    /*
    For the BFV scheme print the plain_modulus parameter.
    */
    if (context_data.parms().scheme() == seal::scheme_type::BFV)
    {
        std::cout << "|   plain_modulus: " << context_data.
            parms().plain_modulus().value() << std::endl;
    }

    std::cout << "\\" << std::endl;
}

// http://pybind11.readthedocs.io/en/stable/classes.html

PYBIND11_MODULE(seal, m) {

  /************** AUXILIARY FUNCTIONS ********************/
  m.def("print_parameters", &print_parameters);
  /*******************************************************/

  /************** VECTOR BINDING ********************/
  py::bind_vector<std::vector<int>>(m, "IntVector");
  py::bind_vector<std::vector<uint32_t>>(m, "UInt32Vector");
  py::bind_vector<std::vector<int64_t>>(m, "Int64Vector");
  py::bind_vector<std::vector<uint64_t>>(m, "UInt64Vector");
  py::bind_vector<std::vector<double>>(m, "DoubleVector");
  py::bind_vector<std::vector<std::complex<double>>>(m, "ComplexVector");
  /**************************************************/

  /***************** ENUMS ***********************/
  py::enum_<scheme_type>(m, "scheme_type")
    .value("none", scheme_type::none)
    .value("BFV", scheme_type::BFV)
    .value("CKKS", scheme_type::CKKS)
    .export_values();

  py::enum_<sec_level_type>(m, "sec_level_type")
    .value("none", sec_level_type::none)
    .value("tc128", sec_level_type::tc128)
    .value("tc192", sec_level_type::tc192)
    .value("tc256", sec_level_type::tc256)
    .export_values();

  py::enum_<mm_prof_opt>(m, "mm_prof_opt_t")
    .value("DEFAULT", mm_prof_opt::DEFAULT)
    .value("FORCE_GLOBAL", mm_prof_opt::FORCE_GLOBAL)
    .value("FORCE_NEW", mm_prof_opt::FORCE_NEW)
    .value("THREAD_LOCAL", mm_prof_opt::FORCE_THREAD_LOCAL)
    .export_values();
  /************************************************/

  /***************** Memory manager and pool handler ***********************/
  py::class_<MemoryPoolHandle>(m, "MemoryPoolHandle")
    .def(py::init<>())
    .def(py::init<const MemoryPoolHandle &>())
    .def_static("new", &MemoryPoolHandle::New,
		"Returns a MemoryPoolHandle pointing to a new memory pool")
    .def_static("thread_local", &MemoryPoolHandle::ThreadLocal,
		"Returns a MemoryPoolHandle pointing to the thread-local memory pool.")
    .def_static("global", &MemoryPoolHandle::Global,
               "Returns a MemoryPoolHandle pointing to the global memory pool")
    .def("pool_count", &MemoryPoolHandle::pool_count,
	 "Returns the number of different allocation sizes. This function returns \
        the number of different allocation sizes the memory pool pointed to by \
        the current MemoryPoolHandle has made. For example, if the memory pool has \
        only allocated two allocations of sizes 128 KB, this function returns 1. \
        If it has instead allocated one allocation of size 64 KB and one of 128 KB, \
        this function returns 2.")
    .def("alloc_byte_count", &MemoryPoolHandle::alloc_byte_count,
	 "Returns the size of allocated memory. This functions returns the total \
        amount of memory (in bytes) allocated by the memory pool pointed to by \
        the current MemoryPoolHandle.")
    .def("use_count", &MemoryPoolHandle::use_count,
	 "Returns the number of MemoryPoolHandle objects sharing this memory pool.");

  py::class_<MemoryManager>(m, "MemoryManager")
    .def_static("GetPool", (MemoryPoolHandle(*)(mm_prof_opt_t)) &MemoryManager::GetPool,
     		"Returns a MemoryPoolHandle according to the currently set memory manager \
                  profile and prof_opt. The following values for prof_opt have an effect \
                  independent of the current profile:				\
                       mm_prof_opt::FORCE_NEW: return MemoryPoolHandle::New() \
                       mm_prof_opt::FORCE_GLOBAL: return MemoryPoolHandle::Global() \
                       mm_prof_opt::FORCE_THREAD_LOCAL: return MemoryPoolHandle::ThreadLocal() \
                  Other values for prof_opt are forwarded to the current profile and, depending \
                  on the profile, may or may not have an effect. The value mm_prof_opt::DEFAULT \
                  will always invoke a default behavior for the current profile.",
		"prof_opt"_a=mm_prof_opt::DEFAULT);
  /***************************************************************************/

  /***************** Modulus ***********************/
  py::class_<CoeffModulus>(m, "CoeffModulus")
    .def_static("BFVDefault", (std::vector<SmallModulus> (*) (std::size_t,
							      sec_level_type)) &CoeffModulus::BFVDefault,
		"Returns a default coefficient modulus for the BFV scheme that guarantees\
        a given security level when using a given poly_modulus_degree, according \
        to the HomomorphicEncryption.org security standard. Note that all security \
        guarantees are lost if the output is used with encryption parameters with \
        a mismatching value for the poly_modulus_degree. \
        The coefficient modulus returned by this function will not perform well \
        if used with the CKKS scheme.",
		     "poly_modulus_degree"_a, "sec_level"_a=sec_level_type::tc128)
    .def_static("Create", (std::vector<SmallModulus> (*) (std::size_t,
							  std::vector<int>)) &CoeffModulus::Create,
		"Returns a custom coefficient modulus suitable for use with the specified \
        poly_modulus_degree. The return value will be a vector consisting of \
        SmallModulus elements representing distinct prime numbers of bit-lengths \
        as given in the bit_sizes parameter. The bit sizes of the prime numbers \
        can be at most 60 bits.",
		"poly_modulus_degree"_a, "bit_sizes"_a);

  py::class_<PlainModulus>(m, "PlainModulus")
    .def_static("Batching", (SmallModulus (*) (std::size_t, int)) &PlainModulus::Batching,
		"Creates a prime number SmallModulus for use as plain_modulus encryption \
        parameter that supports batching with a given poly_modulus_degree.")
    .def_static("Batching", (std::vector<SmallModulus> (*) (std::size_t, std::vector<int>)) &PlainModulus::Batching,
		"Creates several prime number SmallModulus elements that can be used as \
        plain_modulus encryption parameters, each supporting batching with a given \
        poly_modulus_degree.");

  py::class_<SmallModulus>(m, "SmallModulus")
    .def(py::init<>())
    .def(py::init<std::uint64_t>())
    .def(py::init<const SmallModulus &>())
    .def("bit_count", &SmallModulus::bit_count,
	 "Returns the significant bit count of the value of the current SmallModulus.")
    .def("uint64_count", &SmallModulus::uint64_count,
	 "Returns the size (in 64-bit words) of the value of the current SmallModulus.")
    .def("value", &SmallModulus::value,
	 "Returns the value of the current SmallModulus.")
    .def("is_zero", &SmallModulus::is_zero,
	 "Returns whether the value of the current SmallModulus is zero.")
    .def("is_prime", &SmallModulus::is_prime,
	 "Returns whether the value of the current SmallModulus is a prime number.");
   /*************************************************/
  
  /***************** Encryption Parameters ***********************/
  py::class_<EncryptionParameters>(m, "EncryptionParameters")
    .def(py::init<std::uint8_t>())
    .def(py::init<const EncryptionParameters &>())
    .def("set_poly_modulus_degree",
   	 (void (EncryptionParameters::*)(std::size_t)) &EncryptionParameters::set_poly_modulus_degree,
   	 "Sets the degree of the polynomial modulus parameter to the specified value.\
         The polynomial modulus directly affects the number of coefficients in \
         plaintext polynomials, the size of ciphertext elements, the computational \
         performance of the scheme (bigger is worse), and the security level (bigger \
         is better). In Microsoft SEAL the degree of the polynomial modulus must be \
         a power of 2 (e.g.  1024, 2048, 4096, 8192, 16384, or 32768).")
    .def("set_coeff_modulus",
        (void (EncryptionParameters::*)(const std::vector<SmallModulus> &)) &EncryptionParameters::set_coeff_modulus,
        "Sets the coefficient modulus parameter. The coefficient modulus consists \
         of a list of distinct prime numbers, and is represented by a vector of \
         SmallModulus objects. The coefficient modulus directly affects the size \
         of ciphertext elements, the amount of computation that the scheme can \
         perform (bigger is better), and the security level (bigger is worse). In \
         Microsoft SEAL each of the prime numbers in the coefficient modulus must \
         be at most 60 bits, and must be congruent to 1 modulo 2*poly_modulus_degree.")
    .def("set_plain_modulus",
        (void (EncryptionParameters::*)(const SmallModulus &)) &EncryptionParameters::set_plain_modulus,
        "Sets the plaintext modulus parameter. The plaintext modulus is an integer \
         modulus represented by the SmallModulus class. The plaintext modulus \
         determines the largest coefficient that plaintext polynomials can represent. \
         It also affects the amount of computation that the scheme can perform \
         (bigger is worse). In Microsoft SEAL the plaintext modulus can be at most \
         60 bits long, but can otherwise be any integer. Note, however, that some \
         features (e.g. batching) require the plaintext modulus to be of a particular \
         form.")
    .def("set_plain_modulus",
        (void (EncryptionParameters::*)(std::uint64_t)) &EncryptionParameters::set_plain_modulus,
        "Sets the plaintext modulus parameter. The plaintext modulus is an integer \
         modulus represented by the SmallModulus class. The plaintext modulus \
         determines the largest coefficient that plaintext polynomials can represent. \
         It also affects the amount of computation that the scheme can perform \
         (bigger is worse). In Microsoft SEAL the plaintext modulus can be at most \
         60 bits long, but can otherwise be any integer. Note, however, that some \
         features (e.g. batching) require the plaintext modulus to be of a particular \
         form.")
    .def("set_random_generator",
   	 (void (EncryptionParameters::*)(std::shared_ptr<seal::UniformRandomGeneratorFactory>))
	        &EncryptionParameters::set_random_generator,
   	 "Sets the random number generator factory to use for encryption. By default,\
         the random generator is set to UniformRandomGeneratorFactory::default_factory().\
         Setting this value allows a user to specify a custom random number generator\
         source.")
    .def("scheme", &EncryptionParameters::scheme, "Returns the encpytion scheme type")
    .def("poly_modulus_degree", &EncryptionParameters::poly_modulus_degree,
	 "Returns the polynomial modulus parameter")
    .def("coeff_modulus", &EncryptionParameters::coeff_modulus,
	 "Returns a const reference to the currently set coefficient modulus parameter")
    .def("plain_modulus", &EncryptionParameters::plain_modulus,
	 "Returns a const reference to the currently set plaintext modulus parameter")
    .def("random_generator", &EncryptionParameters::random_generator,
	 "Returns a pointer to the random number generator factory to use for encryption");
    /*.def("save", (void (EncryptionParameters::*)(std::string &,
						 seal::compr_mode_type)) &EncryptionParameters::python_save,
        "Saves EncryptionParameters to an output stream. The output is in binary\
         format and is not human-readable. The output stream must have the 'binary'\
         flag set.")
    .def("load", (void (EncryptionParameters::*)(std::string &)) &EncryptionParameters::python_load,
   	 "Loads EncryptionParameters from an input stream overwriting the current\
         EncryptionParameters.");*/
  /***************************************************************/

  /***************** SEALContext ***********************/
  /** NOTE: std:shared_ptr is needed here because  
      "The binding generator for classes, class_, can be passed a template type that 
       denotes a special holder type that is used to manage references to the object. 
       If no such holder type template argument is given, the default for a type named 
       Type is std::unique_ptr<Type>, which means that the object is deallocated when 
       Python’s reference count goes to zero."
    See: https://pybind11.readthedocs.io/en/stable/advanced/smart_ptrs.html#std-shared-ptr
         https://github.com/pybind/pybind11/issues/956
   */
  py::class_<SEALContext, std::shared_ptr<SEALContext>>(m, "SEALContext")
    .def_static("Create", (std::shared_ptr<SEALContext>(*)(const EncryptionParameters &,
						    bool, sec_level_type)) &SEALContext::Create,
	 "Creates an instance of SEALContext and performs several pre-computations \
         on the given EncryptionParameters.",
		"parms"_a, "expand_mod_chain"_a=true, "sec_level"_a=sec_level_type::tc128)
    .def("get_context_data", (std::shared_ptr<SEALContext::ContextData>(SEALContext::*)(parms_id_type) const)
	 &SEALContext::get_context_data,
	 "Returns the ContextData corresponding to encryption parameters with a given \
        parms_id. If parameters with the given parms_id are not found then the\
        function returns nullptr.")
    .def("key_context_data", (std::shared_ptr<SEALContext::ContextData>(SEALContext::*)() const) &SEALContext::key_context_data,
	"Returns the ContextData corresponding to encryption parameters that are \
        used for keys. ")
    .def("first_context_data", (std::shared_ptr<SEALContext::ContextData>(SEALContext::*)() const) &SEALContext::first_context_data,
        "Returns the ContextData corresponding to the first encryption parameters \
        that are used for data.")
    .def("last_context_data", (std::shared_ptr<SEALContext::ContextData>(SEALContext::*)() const) &SEALContext::last_context_data,
	 "Returns the ContextData corresponding to the last encryption parameters \
        that are used for data.")
    .def("parameters_set", (std::shared_ptr<SEALContext::ContextData>(SEALContext::*)() const) &SEALContext::parameters_set,
	 "Returns whether the encryption parameters are valid.")
    .def("qualifiers", (EncryptionParameterQualifiers (SEALContext::*)() const) &SEALContext::qualifiers,
	 "Returns a copy of EncryptionParameterQualifiers corresponding to the \
           current encryption parameters. Note that to change the qualifiers it is \
           necessary to create a new instance of SEALContext once appropriate changes \
           to the encryption parameters have been made.")
    .def("key_parms_id", (parms_id_type& (SEALContext::*)() const) &SEALContext::key_parms_id,
			  "Returns a parms_id_type corresponding to the set of encryption \
                            parameters that are used for keys.")
    .def("first_parms_id", (parms_id_type& (SEALContext::*)() const) &SEALContext::first_parms_id,
	 "Returns a parms_id_type corresponding to the first encryption \
          parameters that are used for data.")
    .def("last_parms_id", (parms_id_type& (SEALContext::*)() const) &SEALContext::last_parms_id,
	 "Returns a parms_id_type corresponding to the last encryption \
          parameters that are used for data.")
    .def("using_keyswitching", (bool (SEALContext::*)() const) &SEALContext::using_keyswitching,
	 "Returns whether the coefficient modulus supports \
          keyswitching. In practice, support for keyswitching is required by Evaluator::relinearize, \
          Evaluator::apply_galois, and all rotation and conjugation operations. For \
          keyswitching to be available, the coefficient modulus parameter must consist \
          of at least two prime number factors.");

  py::class_<SEALContext::ContextData, std::shared_ptr<SEALContext::ContextData>>(m, "ContextData")
    .def("parms", (EncryptionParameters& (SEALContext::ContextData::*)() const noexcept) &SEALContext::ContextData::parms,
	 "Returns a const reference to the underlying encryption parameters.")
    .def("parms_id", (parms_id_type& (SEALContext::ContextData::*)() const noexcept) &SEALContext::ContextData::parms_id,
	 "Returns the parms_id of the current parameters.")
    .def("qualifiers", (EncryptionParameterQualifiers (SEALContext::ContextData::*)() const noexcept)
	 &SEALContext::ContextData::qualifiers,
	 "Returns a copy of EncryptionParameterQualifiers corresponding to the \
            current encryption parameters. Note that to change the qualifiers it is \
            necessary to create a new instance of SEALContext once appropriate changes \
            to the encryption parameters have been made.")
    .def("chain_index", (std::size_t (SEALContext::ContextData::*)() const noexcept) &SEALContext::ContextData::chain_index,
	 "Returns the index of the parameter set in a chain. The initial parameters \
            have index 0 and the index increases sequentially in the parameter chain.")
    .def("next_context_data", (std::shared_ptr<const SEALContext::ContextData>(SEALContext::ContextData::*)() const noexcept)
	 &SEALContext::ContextData::next_context_data,
	 "Returns a shared_ptr to the context data corresponding to the next parameters \
            in the modulus switching chain. If the current data is the last one in the \
            chain, then the result is nullptr.");
    

  py::class_<EncryptionParameterQualifiers>(m, "EncryptionParameterQualifiers")
    .def_readonly("parameters_set", &EncryptionParameterQualifiers::parameters_set)
    .def_readonly("using_fft", &EncryptionParameterQualifiers::using_fft)
    .def_readonly("using_ntt", &EncryptionParameterQualifiers::using_ntt)
    .def_readonly("using_batching", &EncryptionParameterQualifiers::using_batching)
    .def_readonly("using_fast_plain_lift", &EncryptionParameterQualifiers::using_fast_plain_lift)
    .def_readonly("using_descending_modulus_chain", &EncryptionParameterQualifiers::using_descending_modulus_chain)
    .def_readonly("sec_level", &EncryptionParameterQualifiers::sec_level);
  /*****************************************************/

  /***************** KeyGenerator ***********************/
  py::class_<KeyGenerator>(m, "KeyGenerator")
    .def(py::init<std::shared_ptr<SEALContext>>())
    .def(py::init<std::shared_ptr<SEALContext>, const SecretKey &>())
    .def(py::init<std::shared_ptr<SEALContext>, const SecretKey &, const PublicKey &>())
    .def("secret_key", (const SecretKey& (KeyGenerator::*)() const) &KeyGenerator::secret_key,
	 "Returns a const reference to the secret key.")
    .def("public_key", (const PublicKey& (KeyGenerator::*)() const) &KeyGenerator::public_key,
	 "Returns a const reference to the public key.")
    .def("relin_keys", (RelinKeys (KeyGenerator::*)()) &KeyGenerator::relin_keys,
	 "Generates and returns relinearization keys.")
    .def("galois_keys", (GaloisKeys (KeyGenerator::*)()) &KeyGenerator::galois_keys,
	 "Generates and returns Galois keys. This function creates logarithmically \
        many (in degree of the polynomial modulus) Galois keys that is sufficient \
        to apply any Galois automorphism (e.g. rotations) on encrypted data. Most \
        users will want to use this overload of the function.");

  py::class_<KSwitchKeys>(m, "KSwitchKeys")
    .def(py::init<>())
    .def("parms_id", (parms_id_type& (KSwitchKeys::*)() noexcept) &KSwitchKeys::parms_id,
	 "Returns a reference to parms_id.");

  py::class_<RelinKeys, KSwitchKeys>(m, "RelinKeys")
    .def_static("get_index", (std::size_t (*)(std::size_t)) &RelinKeys::get_index,
		" Returns the index of a relinearization key in the backing KSwitchKeys \
        instance that corresponds to the given secret key power, assuming that \
        it exists in the backing KSwitchKeys.", 
		"key_power"_a);

  py::class_<GaloisKeys, KSwitchKeys>(m, "GaloisKeys");
 
  /*****************************************************/

  /***************** Public and private keys ***********************/
  py::class_<PublicKey>(m, "PublicKey")
    .def(py::init<>())
    .def(py::init<PublicKey &>())
    .def("parms_id", (parms_id_type& (PublicKey::*)() noexcept) &PublicKey::parms_id,
	 "Returns a reference to parms_id.");
  py::class_<SecretKey>(m, "SecretKey")
    .def(py::init<>())
    .def(py::init<SecretKey &>())
    .def("parms_id", (parms_id_type& (SecretKey::*)() noexcept) &SecretKey::parms_id,
	 "Returns a reference to parms_id.");

  /*****************************************************************/

  /***************** Plaintext ***********************/
  py::class_<Plaintext>(m, "Plaintext")
    .def(py::init<MemoryPoolHandle>(), "pool"_a=MemoryManager::GetPool())
    .def(py::init<std::size_t, MemoryPoolHandle>(),
	 "coeff_count"_a, "pool"_a=MemoryManager::GetPool())
    .def(py::init<std::size_t, std::size_t, MemoryPoolHandle>(),
	 "capacity"_a, "coeff_count"_a, "pool"_a=MemoryManager::GetPool())
    .def(py::init<const std::string &, MemoryPoolHandle>(),
	 "hex_poly"_a, "pool"_a=MemoryManager::GetPool())
    .def(py::init<const Plaintext &>(),
	 "copy"_a)
    .def(py::init<const Plaintext &, MemoryPoolHandle>(),
	 "copy"_a, "pool"_a=MemoryManager::GetPool())
    .def("reserve", (void (Plaintext::*)(std::size_t)) &Plaintext::reserve,
	 "Allocates enough memory to accommodate the backing array of a plaintext \
        with given capacity.")
    .def("shrink_to_fit", &Plaintext::shrink_to_fit,
	 "Allocates enough memory to accommodate the backing array of the current \
        plaintext and copies it over to the new location. This function is meant \
        to reduce the memory use of the plaintext to smallest possible and can be \
        particularly important after modulus switching.")
    .def("release", &Plaintext::release,
	 "Resets the plaintext. This function releases any memory allocated by the \
        plaintext, returning it to the memory pool.")
    .def("resize", (void (Plaintext::*)(std::size_t)) &Plaintext::resize,
	 "Resizes the plaintext to have a given coefficient count. The plaintext \
        is automatically reallocated if the new coefficient count does not fit in \
        the current capacity.")
    .def("set_zero", (void (Plaintext::*)(std::size_t, std::size_t)) &Plaintext::set_zero,
	 "Sets a given range of coefficients of a plaintext polynomial to zero; does \
        nothing if length is zero.")
    .def("set_zero", (void (Plaintext::*)(std::size_t)) &Plaintext::set_zero,
	 "Sets the plaintext polynomial coefficients to zero starting at a given index.")
    .def("set_zero", (void (Plaintext::*)()) &Plaintext::set_zero,
	 "Sets the plaintext polynomial to zero.")
    .def("to_string", (std::string (Plaintext::*)() const) &Plaintext::to_string,
	 "Returns a human-readable string description of the plaintext polynomial.\
        The returned string is of the form '7FFx^3 + 1x^1 + 3' with a format \
        summarized by the following: \
        1. Terms are listed in order of strictly decreasing exponent\
        2. Coefficient values are non-negative and in hexadecimal format (hexadecimal\
        letters are in upper-case)\
        3. Exponents are positive and in decimal format\
        4. Zero coefficient terms (including the constant term) are omitted unless\
        the polynomial is exactly 0 (see rule 9)\
        5. Term with the exponent value of one is written as x^1\
        6. Term with the exponent value of zero (the constant term) is written as\
        just a hexadecimal number without x or exponent\
        7. Terms are separated exactly by <space>+<space>\
        8. Other than the +, no other terms have whitespace\
        9. If the polynomial is exactly 0, the string '0' is returned")
    .def("parms_id", (parms_id_type& (Plaintext::*)() noexcept) &Plaintext::parms_id,
	 "Returns a reference to parms_id.")
    .def("scale", (double & (Plaintext::*) ()) &Plaintext::scale,
	 "Returns a reference to the scale. This is only needed when using the CKKS \
        encryption scheme. The user should have little or no reason to ever change \
        the scale by hand.");
  /*****************************************************/

  /***************** Ciphertext ***********************/
  py::class_<Ciphertext>(m, "Ciphertext")
    .def(py::init<MemoryPoolHandle>(), "pool"_a=MemoryManager::GetPool())
    .def(py::init<std::shared_ptr<SEALContext>, MemoryPoolHandle>(),
	 "context"_a, "pool"_a=MemoryManager::GetPool())
    .def(py::init<std::shared_ptr<SEALContext>, parms_id_type, MemoryPoolHandle>(),
	 "context"_a, "parms_id"_a, "pool"_a=MemoryManager::GetPool())
    .def(py::init<std::shared_ptr<SEALContext>, parms_id_type, std::size_t, MemoryPoolHandle>(),
	 "context"_a, "parms_id"_a, "size_capacity"_a, "pool"_a=MemoryManager::GetPool())
    .def(py::init<const Ciphertext &, MemoryPoolHandle>(),
	 "copy"_a, "pool"_a=MemoryManager::GetPool())
    .def("size", (std::size_t (Ciphertext::*) ()) &Ciphertext::size,
	 "Returns the size of the ciphertext.")
    .def("scale", (double & (Ciphertext::*) ()) &Ciphertext::scale,
	 "Returns a reference to the scale. This is only needed when using the \
        CKKS encryption scheme. The user should have little or no reason to ever \
        change the scale by hand.")
    .def("set_scale", (void (Ciphertext::*) (double)) &Ciphertext::set_scale,
        "Sets the scale of a Ciphertext")
    .def("parms_id", (parms_id_type& (Ciphertext::*)() noexcept) &Ciphertext::parms_id,
	 "Returns a reference to parms_id.");
  /*****************************************************/

  /***************** Encryptor ***********************/
  py::class_<Encryptor>(m, "Encryptor")
    .def(py::init<std::shared_ptr<SEALContext>, const PublicKey &>())
    .def(py::init<std::shared_ptr<SEALContext>, const SecretKey &>())
    .def(py::init<std::shared_ptr<SEALContext>, const PublicKey &, const SecretKey &>())
    .def("set_public_key", (void (Encryptor::*)(const PublicKey &)) &Encryptor::set_public_key,
	 "Give a new instance of a public key.")
    .def("set_secret_key", (void (Encryptor::*)(const SecretKey &)) &Encryptor::set_secret_key,
	 "Give a new instance of a secret key.")
    .def("encrypt", (void (Encryptor::*)(const Plaintext &, Ciphertext &,
					 MemoryPoolHandle)) &Encryptor::encrypt,
	 "Encrypts a plaintext with the public key and stores the result in \
        destination. The encryption parameters for the resulting ciphertext \
        correspond to: \
        1) in BFV, the highest (data) level in the modulus switching chain, \
        2) in CKKS, the encryption parameters of the plaintext. \
        Dynamic memory allocations in the process are allocated from the memory \
        pool pointed to by the given MemoryPoolHandle.",
	 "plain"_a, "destination"_a, "pool"_a=MemoryManager::GetPool())
    .def("encrypt_zero", (void (Encryptor::*)(Ciphertext &,
					      MemoryPoolHandle) const) &Encryptor::encrypt_zero,
	 "Encrypts a zero plaintext with the public key and stores the result in \
        destination. The encryption parameters for the resulting ciphertext \
        correspond to the highest (data) level in the modulus switching chain. \
        Dynamic memory allocations in the process are allocated from the memory \
        pool pointed to by the given MemoryPoolHandle.",
	 "destination"_a, "pool"_a=MemoryManager::GetPool())
    .def("encrypt_zero", (void (Encryptor::*)(parms_id_type, Ciphertext &,
					      MemoryPoolHandle) const) &Encryptor::encrypt_zero,
	 "Encrypts a zero plaintext with the public key and stores the result in \
        destination. The encryption parameters for the resulting ciphertext \
        correspond to the given parms_id. Dynamic memory allocations in the process \
        are allocated from the memory pool pointed to by the given MemoryPoolHandle."
	 "parms_id"_a, "destination"_a, "pool"_a=MemoryManager::GetPool())
    .def("encrypt_symmetric", (void (Encryptor::*)(const Plaintext &, Ciphertext &,
						   MemoryPoolHandle)) &Encryptor::encrypt_symmetric,
	 "Encrypts a plaintext with the secret key and stores the result in \
        destination. The encryption parameters for the resulting ciphertext \
        correspond to: \
        1) in BFV, the highest (data) level in the modulus switching chain,\
        2) in CKKS, the encryption parameters of the plaintext. \
        Dynamic memory allocations in the process are allocated from the memory\
        pool pointed to by the given MemoryPoolHandle.",
	 "plain"_a, "destination"_a, "pool"_a=MemoryManager::GetPool())
    .def("encrypt_zero_symmetric", (void (Encryptor::*)(Ciphertext &,
							MemoryPoolHandle)) &Encryptor::encrypt_symmetric,
	 "Encrypts a zero plaintext with the secret key and stores the result in \
        destination. The encryption parameters for the resulting ciphertext \
        correspond to the highest (data) level in the modulus switching chain. \
        Dynamic memory allocations in the process are allocated from the memory \
        pool pointed to by the given MemoryPoolHandle."
	 "destination"_a, "pool"_a=MemoryManager::GetPool())
    .def("encrypt_zero_symmetric", (void (Encryptor::*)(parms_id_type,
							Ciphertext &,
							MemoryPoolHandle)) &Encryptor::encrypt_symmetric,
	 "Encrypts a zero plaintext with the secret key and stores the result in \
        destination. The encryption parameters for the resulting ciphertext \
        correspond to the given parms_id. Dynamic memory allocations in the process \
        are allocated from the memory pool pointed to by the given MemoryPoolHandle.",
	 "parms_id"_a, "destination"_a, "pool"_a=MemoryManager::GetPool());
  /*****************************************************/

  /***************** Decryptor ***********************/
  py::class_<Decryptor>(m, "Decryptor")
    .def(py::init<std::shared_ptr<SEALContext>, const SecretKey &>())
    .def("decrypt", (void (Decryptor::*)(const Ciphertext &, Plaintext &)) &Decryptor::decrypt,
	 "Decrypts a Ciphertext and stores the result in the destination parameter.")
    .def("invariant_noise_budget", (int (Decryptor::*) (const Ciphertext &)) &Decryptor::invariant_noise_budget,
	"Computes the invariant noise budget (in bits) of a ciphertext. The \
        invariant noise budget measures the amount of room there is for the noise \
        to grow while ensuring correct decryptions. This function works only with \
        the BFV scheme. \
        @par Invariant Noise Budget \
        The invariant noise polynomial of a ciphertext is a rational coefficient \
        polynomial, such that a ciphertext decrypts correctly as long as the \
        coefficients of the invariantnoise polynomial are of absolute value less \
        than 1/2. Thus, we call the infinity-norm of the invariant noise polynomial \
        the invariant noise, and for correct decryption requireit to be less than \
        1/2. If v denotes the invariant noise, we define the invariant noise budget \
        as -log2(2v). Thus, the invariant noise budget starts from some initial \
        value, which depends on the encryption parameters, and decreases when \
        computations are performed. When the budget reaches zero, the ciphertext \
        becomes too noisy to decrypt correctly.");
  /***************************************************/

  /************* Evaluator *****************************/
  py::class_<Evaluator>(m, "Evaluator")
    .def(py::init<std::shared_ptr<SEALContext>>())
    .def("negate_inplace", (void (Evaluator::*)(Ciphertext &)) &Evaluator::negate_inplace,
  	 "Negates a ciphertext")
    .def("negate", (void (Evaluator::*)(Ciphertext &, Ciphertext &)) &Evaluator::negate,
        "Negates a ciphertext and stores the result in the destination parameter"
  	 "encrypted"_a, "destination"_a)
    .def("add_inplace", (void (Evaluator::*)(Ciphertext &,
  					     const Ciphertext &)) &Evaluator::add_inplace,
  	 "Adds two ciphertexts. This function adds together encrypted1 and encrypted2 \
         and stores the result in encrypted1.",
  	 "encrypted1"_a, "encrypted2"_a)
    .def("add", (void (Evaluator::*)(const Ciphertext &, const Ciphertext &,
				     Ciphertext &)) &Evaluator::add,
  	 "Adds two ciphertexts. This function adds together encrypted1 and encrypted2 \
         and stores the result in the destination parameter.",
  	 "encrypted1"_a, "encrypted2"_a, "destination"_a)
    .def("add_many", (void (Evaluator::*)(const std::vector<Ciphertext> &,
  					  Ciphertext &)) &Evaluator::add_many,
  	 "Adds together a vector of ciphertexts and stores the result in the destination parameter.",
  	 "encrypteds"_a, "destination"_a)
    .def("sub_inplace", (void (Evaluator::*)(Ciphertext &,
  					     const Ciphertext &)) &Evaluator::sub_inplace,
  	 "Subtracts two ciphertexts. This function computes the difference of encrypted1 \
         and encrypted2, and stores the result in encrypted1.",
  	 "encrypted1"_a, "encrypted2"_a)
    .def("sub", (void (Evaluator::*)(const Ciphertext &, const Ciphertext &,
				     Ciphertext &)) &Evaluator::sub,
	 "Subtracts two ciphertexts. This function computes the difference of encrypted1\
         and encrypted2 and stores the result in the destination parameter.",
  	 "encrypted1"_a, "encrypted2"_a, "destination"_a)
    .def("multiply_inplace", (void (Evaluator::*)(Ciphertext &, const Ciphertext &,
     						  MemoryPoolHandle)) &Evaluator::multiply_inplace,
     	 "Multiplies two ciphertexts. This functions computes the product of encrypted1 \
          and encrypted2 and stores the result in encrypted1. Dynamic memory allocations \
          in the process are allocated from the memory pool pointed to by the given \
          MemoryPoolHandle.",
     	 "encrypted1"_a, "encrypted2"_a, "pool"_a=MemoryManager::GetPool())
    .def("multiply", (void (Evaluator::*)(const Ciphertext &, const Ciphertext &,
     					  Ciphertext &, MemoryPoolHandle)) &Evaluator::multiply,
    	 "Multiplies two ciphertexts. This functions computes the product of encrypted1 \
          and encrypted2 and stores the result in the destination parameter. Dynamic \
          memory allocations in the process are allocated from the memory pool pointed \
          to by the given MemoryPoolHandle.",
	 "encrypted1"_a, "encrypted2"_a, "destination"_a, "pool"_a=MemoryManager::GetPool())
    .def("square_inplace", (void (Evaluator::*)(Ciphertext &,
     						MemoryPoolHandle)) &Evaluator::square_inplace,
     	 "Squares a ciphertext. This functions computes the square of encrypted. Dynamic \
          memory allocations in the process are allocated from the memory pool pointed \
          to by the given MemoryPoolHandle.",
     	 "encrypted1"_a, "pool"_a=MemoryManager::GetPool())
    .def("square", (void (Evaluator::*)(const Ciphertext &, Ciphertext &,
     					MemoryPoolHandle)) &Evaluator::square,
     	 "Squares a ciphertext. This functions computes the square of encrypted and \
          stores the result in the destination parameter. Dynamic memory allocations \
          in the process are allocated from the memory pool pointed to by the given \
          MemoryPoolHandle.",
     	 "encrypted1"_a, "destination"_a, "pool"_a=MemoryManager::GetPool())
    .def("relinearize_inplace", (void (Evaluator::*)(Ciphertext &, const RelinKeys &,
						     MemoryPoolHandle)) &Evaluator::relinearize_inplace,
	 "Relinearizes a ciphertext. This functions relinearizes encrypted, reducing \
           its size down to 2. If the size of encrypted is K+1, the given relinearization \
           keys need to have size at least K-1. Dynamic memory allocations in the \
           process are allocated from the memory pool pointed to by the given \
           MemoryPoolHandle."
	 "encrypted"_a, "relin_keys"_a, "pool"_a=MemoryManager::GetPool())
    .def("relinearize", (void (Evaluator::*)(const Ciphertext &, const RelinKeys&,
					     const Ciphertext&, MemoryPoolHandle)) &Evaluator::relinearize,
	 "Relinearizes a ciphertext. This functions relinearizes encrypted, reducing \
        its size down to 2, and stores the result in the destination parameter. \
        If the size of encrypted is K+1, the given relinearization keys need to \
        have size at least K-1. Dynamic memory allocations in the process are allocatedi \
        from the memory pool pointed to by the given MemoryPoolHandle.",
	 "encrypted"_a, "relin_keys"_a, "destination"_a, "pool"_a=MemoryManager::GetPool())
    .def("mod_switch_to_next", (void (Evaluator::*)(const Ciphertext &, Ciphertext &,
						    MemoryPoolHandle)) &Evaluator::mod_switch_to_next,
	 "Given a ciphertext encrypted modulo q_1...q_k, this function switches the \
        modulus down to q_1...q_{k-1} and stores the result in the destination \
        parameter. Dynamic memory allocations in the process are allocated from \
        the memory pool pointed to by the given MemoryPoolHandle."
     	 "encrypted"_a, "destination"_a, "pool"_a=MemoryManager::GetPool())
    .def("mod_switch_to_next_inplace", (void (Evaluator::*)(Ciphertext &,
							    MemoryPoolHandle)) &Evaluator::mod_switch_to_next_inplace,
	 "Given a ciphertext encrypted modulo q_1...q_k, this function switches the \
        modulus down to q_1...q_{k-1}. Dynamic memory allocations in the process \
        are allocated from the memory pool pointed to by the given MemoryPoolHandle."
     	 "encrypted"_a, "pool"_a=MemoryManager::GetPool())
    .def("mod_switch_to_next_inplace", (void (Evaluator::*)(Plaintext &))&Evaluator::mod_switch_to_next_inplace,
	 "Modulus switches an NTT transformed plaintext from modulo q_1...q_k down \
        to modulo q_1...q_{k-1}."
     	 "plain"_a)
    .def("mod_switch_to_next", (void (Evaluator::*)(const Plaintext &, Plaintext &)) &Evaluator::mod_switch_to_next,
	 "Modulus switches an NTT transformed plaintext from modulo q_1...q_k down \
        to modulo q_1...q_{k-1} and stores the result in the destination parameter."
     	 "plain"_a, "destination"_a)
    .def("mod_switch_to_inplace", (void (Evaluator::*)(Ciphertext &, parms_id_type, 
						       MemoryPoolHandle)) &Evaluator::mod_switch_to_inplace,
	 "Given a ciphertext encrypted modulo q_1...q_k, this function switches the \
        modulus down until the parameters reach the given parms_id. Dynamic memory \
        allocations in the process are allocated from the memory pool pointed to \
        by the given MemoryPoolHandle."
     	 "encrypted"_a, "parms_id"_a, "pool"_a=MemoryManager::GetPool())
    .def("mod_switch_to", (void (Evaluator::*)(const Ciphertext &, parms_id_type, 
					       Ciphertext &, MemoryPoolHandle)) &Evaluator::mod_switch_to,
	 "Given a ciphertext encrypted modulo q_1...q_k, this function switches the \
        modulus down until the parameters reach the given parms_id and stores the \
        result in the destination parameter. Dynamic memory allocations in the process \
        are allocated from the memory pool pointed to by the given MemoryPoolHandle."
     	 "encrypted"_a, "parms_id"_a, "destination"_a, "pool"_a=MemoryManager::GetPool())
    .def("mod_switch_to_inplace", (void (Evaluator::*)(Plaintext &, parms_id_type)) &Evaluator::mod_switch_to_inplace,
	 " Given an NTT transformed plaintext modulo q_1...q_k, this function switches \
        the modulus down until the parameters reach the given parms_id and stores \
        the result in the destination parameter."
     	 "plain"_a, "parms_id"_a) 
    .def("mod_switch_to", (void (Evaluator::*)(const Plaintext &, parms_id_type, Plaintext &)) &Evaluator::mod_switch_to,
	 "Given an NTT transformed plaintext modulo q_1...q_k, this function switches \
        the modulus down until the parameters reach the given parms_id and stores \
        the result in the destination parameter."
     	 "plain"_a, "parms_id"_a, "destination"_a)
    .def("rescale_to_next", (void (Evaluator::*)(const Ciphertext &, Ciphertext &, MemoryPoolHandle)) &Evaluator::rescale_to_next,
         "",
	 "encrypted"_a, "destination"_a, "pool"_a=MemoryManager::GetPool())
    .def("rescale_to_next_inplace", (void (Evaluator::*)(Ciphertext &, MemoryPoolHandle)) &Evaluator::rescale_to_next_inplace,
         "",
	 "encrypted"_a, "pool"_a=MemoryManager::GetPool())
    .def("rescale_to_inplace", (void (Evaluator::*)(Ciphertext &, parms_id_type, MemoryPoolHandle)) &Evaluator::rescale_to_inplace,
         "",
	 "encrypted"_a, "parms_id"_a, "pool"_a=MemoryManager::GetPool())
    .def("rescale_to", (void (Evaluator::*)(const Ciphertext &, parms_id_type, Ciphertext &, MemoryPoolHandle)) &Evaluator::rescale_to,
         "",
	 "encrypted"_a, "parms_id"_a, "destination"_a, "pool"_a=MemoryManager::GetPool())
    .def("multiply_many", (void (Evaluator::*)(const std::vector<Ciphertext> &, const RelinKeys &, 
					       Ciphertext &, MemoryPoolHandle)) &Evaluator::multiply_many,
	 "", 
  	 "encrypteds"_a, "relin_keys"_a, "destination"_a, "pool"_a=MemoryManager::GetPool())
    .def("exponentiate_inplace", (void (Evaluator::*)(Ciphertext &, std::uint64_t, const RelinKeys &, 
					       MemoryPoolHandle)) &Evaluator::exponentiate_inplace,
	 "", 
  	 "encrypted"_a, "exponent"_a, "relin_keys"_a, "pool"_a=MemoryManager::GetPool())
    .def("exponentiate", (void (Evaluator::*)(const Ciphertext &, std::uint64_t, const RelinKeys &, 
					       Ciphertext &, MemoryPoolHandle)) &Evaluator::exponentiate,
	 "", 
  	 "encrypted"_a, "exponent"_a, "relin_keys"_a, "destination"_a, "pool"_a=MemoryManager::GetPool())
    .def("add_plain_inplace", (void (Evaluator::*)(const Ciphertext &, const Plaintext &)) &Evaluator::add_plain_inplace,
	 "", 
  	 "encrypted"_a, "plain"_a)
    .def("add_plain", (void (Evaluator::*)(const Ciphertext &, const Plaintext &,
					   Ciphertext &)) &Evaluator::add_plain,
	 "", 
  	 "encrypted"_a, "plain"_a, "destination"_a)
    .def("sub_plain_inplace", (void (Evaluator::*)(const Ciphertext &, const Plaintext &)) &Evaluator::sub_plain_inplace,
	 "", 
  	 "encrypted"_a, "plain"_a)
    .def("sub_plain", (void (Evaluator::*)(const Ciphertext &, const Plaintext &,
					   Ciphertext &)) &Evaluator::sub_plain,
	 "", 
  	 "encrypted"_a, "plain"_a, "destination"_a)
    .def("multiply_plain_inplace", (void (Evaluator::*)(Ciphertext &, const Plaintext &, 
					       MemoryPoolHandle)) &Evaluator::multiply_plain_inplace,
	 "", 
  	 "encrypted"_a, "plain"_a, "pool"_a=MemoryManager::GetPool())
    .def("multiply_plain", (void (Evaluator::*)(const Ciphertext &, const Plaintext &,
					       Ciphertext &, MemoryPoolHandle)) &Evaluator::multiply_plain,
	 "", 
  	 "encrypted"_a, "plain"_a, "destination"_a, "pool"_a=MemoryManager::GetPool())
    .def("transform_to_ntt_inplace", (void (Evaluator::*)(Plaintext &, parms_id_type,  
					       MemoryPoolHandle)) &Evaluator::transform_to_ntt_inplace,
	 "", 
  	 "plain"_a, "parms_id"_a, "pool"_a=MemoryManager::GetPool())
    .def("transform_to_ntt", (void (Evaluator::*)(const Plaintext &, parms_id_type, Plaintext &,
					       MemoryPoolHandle)) &Evaluator::multiply_plain,
	 "", 
  	 "plain"_a, "parms_id"_a, "destination_ntt"_a, "pool"_a=MemoryManager::GetPool())
    .def("transform_to_ntt_inplace", (void (Evaluator::*)(Ciphertext &)) &Evaluator::transform_to_ntt_inplace,
	 "", 
  	 "encrypted"_a)
    .def("transform_to_ntt", (void (Evaluator::*)(const Ciphertext &, Ciphertext &)) &Evaluator::transform_to_ntt,
	 "", 
  	 "encrypted"_a, "destination_ntt"_a)
    .def("transform_from_ntt_inplace", (void (Evaluator::*)(Ciphertext &)) &Evaluator::transform_from_ntt_inplace,
	 "", 
  	 "encrypted_ntt"_a)
    .def("transform_from_ntt", (void (Evaluator::*)(const Ciphertext &, Ciphertext &)) &Evaluator::transform_from_ntt,
	 "", 
  	 "encrypted_ntt"_a, "destination_ntt"_a)
    .def("apply_galois_inplace", (void (Evaluator::*)(Ciphertext &, std::uint64_t, const GaloisKeys &,
						      MemoryPoolHandle)) &Evaluator::apply_galois_inplace,
	 "", 
  	 "encrypted"_a, "galois_elt"_a, "galois_keys"_a, "pool"_a=MemoryManager::GetPool())
    .def("apply_galois", (void (Evaluator::*)(const Ciphertext &, std::uint64_t, const GaloisKeys &,
					      Ciphertext &, MemoryPoolHandle)) &Evaluator::apply_galois,
	 "", 
  	 "encrypted"_a, "galois_elt"_a, "galois_keys"_a, "destination"_a, "pool"_a=MemoryManager::GetPool())
    .def("rotate_rows_inplace", (void (Evaluator::*)(Ciphertext &, int, const GaloisKeys &,
						      MemoryPoolHandle)) &Evaluator::rotate_rows_inplace,
	 "", 
  	 "encrypted"_a, "steps"_a, "galois_keys"_a, "pool"_a=MemoryManager::GetPool())
    .def("rotate_rows", (void (Evaluator::*)(const Ciphertext &, int, const GaloisKeys &,
					     Ciphertext &, MemoryPoolHandle)) &Evaluator::rotate_rows,
	 "", 
	 "encrypted"_a, "steps"_a, "galois_keys"_a, "destination"_a, "pool"_a=MemoryManager::GetPool())
    .def("rotate_columns_inplace", (void (Evaluator::*)(Ciphertext &, const GaloisKeys &,
						      MemoryPoolHandle)) &Evaluator::rotate_columns_inplace,
	 "", 
  	 "encrypted"_a, "galois_keys"_a, "pool"_a=MemoryManager::GetPool())
    .def("rotate_columns", (void (Evaluator::*)(const Ciphertext &, const GaloisKeys &,
					     Ciphertext &, MemoryPoolHandle)) &Evaluator::rotate_columns,
	 "", 
	 "encrypted"_a, "galois_keys"_a, "destination"_a, "pool"_a=MemoryManager::GetPool())
    .def("rotate_vector_inplace", (void (Evaluator::*)(Ciphertext &, int, const GaloisKeys &,
						      MemoryPoolHandle)) &Evaluator::rotate_vector_inplace,
	 "", 
  	 "encrypted"_a, "steps"_a, "galois_keys"_a, "pool"_a=MemoryManager::GetPool())
    .def("rotate_vector", (void (Evaluator::*)(const Ciphertext &, int, const GaloisKeys &,
					     Ciphertext &, MemoryPoolHandle)) &Evaluator::rotate_vector,
	 "", 
	 "encrypted"_a, "steps"_a, "galois_keys"_a, "destination"_a, "pool"_a=MemoryManager::GetPool())
    .def("complex_conjugate_inplace", (void (Evaluator::*)(Ciphertext &, const GaloisKeys &,
							   MemoryPoolHandle)) &Evaluator::complex_conjugate_inplace,
	 "", 
  	 "encrypted"_a, "galois_keys"_a, "pool"_a=MemoryManager::GetPool())
    .def("complex_conjugate", (void (Evaluator::*)(const Ciphertext &, int, const GaloisKeys &,
					     Ciphertext &, MemoryPoolHandle)) &Evaluator::complex_conjugate,
	 "", 
	 "encrypted"_a, "steps"_a, "galois_keys"_a, "destination"_a, "pool"_a=MemoryManager::GetPool());
  /*****************************************************/

  /************* Encoders *****************************/
  py::class_<IntegerEncoder>(m, "IntegerEncoder")
    .def(py::init<std::shared_ptr<SEALContext>>())
    .def("encode", (Plaintext (IntegerEncoder::*)(std::uint64_t)) &IntegerEncoder::encode,
  	 "Encodes an unsigned integer (represented by std::uint64_t) into a plaintext polynomial.",
	 "value"_a)
    .def("encode", (void (IntegerEncoder::*)(std::uint64_t, Plaintext &)) &IntegerEncoder::encode,
  	 "Encodes an unsigned integer (represented by std::uint64_t) into a plaintext polynomial.",
	 "value"_a, "destination"_a)
    .def("decode_uint64", (std::uint64_t (IntegerEncoder::*)(const Plaintext &)) &IntegerEncoder::decode_uint64,
	 "decodes a plaintext polynomial and returns the result as std::uint64_t.\
        mathematically this amounts to evaluating the input polynomial at x=2.",
  	 "plain"_a)
    .def("encode", (Plaintext (IntegerEncoder::*)(std::uint32_t)) &IntegerEncoder::encode,
  	 "Encodes an unsigned integer (represented by std::uint32_t) into a plaintext polynomial.",
	 "value"_a)
    .def("encode", (void (IntegerEncoder::*)(std::uint32_t, Plaintext &)) &IntegerEncoder::encode,
  	 "Encodes an unsigned integer (represented by std::uint32_t) into a plaintext polynomial.",
	 "value"_a, "destination"_a)
    .def("decode_uint32", (std::uint32_t (IntegerEncoder::*)(const Plaintext &)) &IntegerEncoder::decode_uint32,
	 "decodes a plaintext polynomial and returns the result as std::uint32_t.\
        mathematically this amounts to evaluating the input polynomial at x=2.",
  	 "plain"_a)
     .def("encode", (Plaintext (IntegerEncoder::*)(const BigUInt &)) &IntegerEncoder::encode,
  	 "Encodes an unsigned integer (represented by BigUInt) into a plaintext polynomial.",
	 "value"_a)
    .def("encode", (void (IntegerEncoder::*)(const BigUInt &, Plaintext &)) &IntegerEncoder::encode,
  	 "Encodes an unsigned integer (represented by BigUInt) into a plaintext polynomial.",
	 "value"_a, "destination"_a)
    .def("decode_biguint", (BigUInt (IntegerEncoder::*)(const Plaintext &)) &IntegerEncoder::decode_uint64,
	 "decodes a plaintext polynomial and returns the result as BigUInt.\
        mathematically this amounts to evaluating the input polynomial at x=2.",
  	 "plain"_a)
    .def("encode", (Plaintext (IntegerEncoder::*)(std::int64_t)) &IntegerEncoder::encode,
  	 "Encodes an unsigned integer (represented by std::int64_t) into a plaintext polynomial.",
	 "value"_a)
    .def("encode", (void (IntegerEncoder::*)(std::int64_t, Plaintext &)) &IntegerEncoder::encode,
  	 "Encodes an unsigned integer (represented by std::int64_t) into a plaintext polynomial.",
	 "value"_a, "destination"_a)
    .def("decode_int64", (std::int64_t (IntegerEncoder::*)(const Plaintext &)) &IntegerEncoder::decode_int64,
	 "decodes a plaintext polynomial and returns the result as std::int64_t.\
        mathematically this amounts to evaluating the input polynomial at x=2.",
  	 "plain"_a)
    .def("encode", (Plaintext (IntegerEncoder::*)(std::int32_t)) &IntegerEncoder::encode,
  	 "Encodes an unsigned integer (represented by std::uint32_t) into a plaintext polynomial.",
	 "value"_a)
    .def("encode", (void (IntegerEncoder::*)(std::int32_t, Plaintext &)) &IntegerEncoder::encode,
  	 "Encodes an unsigned integer (represented by std::uint32_t) into a plaintext polynomial.",
	 "value"_a, "destination"_a)
    .def("decode_int32", (std::int32_t (IntegerEncoder::*)(const Plaintext &)) &IntegerEncoder::decode_int32,
	 "decodes a plaintext polynomial and returns the result as std::uint32_t.\
        mathematically this amounts to evaluating the input polynomial at x=2.",
  	 "plain"_a);

  py::class_<BatchEncoder>(m, "BatchEncoder")
    .def(py::init<std::shared_ptr<SEALContext>>())
     .def("encode", (void (BatchEncoder::*)(const std::vector<uint64_t> &, Plaintext &)) &BatchEncoder::encode,
     	 "Creates a plaintext from a given matrix. This function 'batches' a given matrix \
         of integers modulo the plaintext modulus into a plaintext element, and stores \
         the result in the destination parameter. The input vector must have size at most equal \
         to the degree of the polynomial modulus. The first half of the elements represent the \
         first row of the matrix, and the second half represent the second row. The numbers \
         in the matrix can be at most equal to the plaintext modulus for it to represent \
         a valid plaintext.\
         If the destination plaintext overlaps the input values in memory, the behavior of \
         this function is undefined."
        "values"_a, "destination"_a)
    .def("encode", (void (BatchEncoder::*)(const std::vector<int64_t> &, Plaintext &)) &BatchEncoder::encode,
	 "Creates a plaintext from a given matrix. This function 'batches' a given matrix \
        of integers modulo the plaintext modulus into a plaintext element, and stores \
        the result in the destination parameter. The input vector must have size at most equal \
        to the degree of the polynomial modulus. The first half of the elements represent the \
        first row of the matrix, and the second half represent the second row. The numbers \
        in the matrix can be at most equal to the plaintext modulus for it to represent \
        a valid plaintext.\
        If the destination plaintext overlaps the input values in memory, the behavior of \
        this function is undefined."
	 "values"_a, "destination"_a)
     .def("encode", (void (BatchEncoder::*)(Plaintext &, MemoryPoolHandle)) &BatchEncoder::encode,
	 "Creates a plaintext from a given matrix. This function 'batches' a given matrix \
        of integers modulo the plaintext modulus in-place into a plaintext ready to be \
        encrypted. The matrix is given as a plaintext element whose first N/2 coefficients \
        represent the first row of the matrix, and the second N/2 coefficients represent the \
        second row, where N denotes the degree of the polynomial modulus. The input plaintext \
        must have degress less than the polynomial modulus, and coefficients less than the \
        plaintext modulus, i.e. it must be a valid plaintext for the encryption parameters. \
        Dynamic memory allocations in the process are allocated from the memory pool pointed \
        to by the given MemoryPoolHandle.",
	 "plain"_a, "pool"_a=MemoryManager::GetPool())
     .def("decode", (void (BatchEncoder::*)(const Plaintext &, std::vector<uint64_t> &,
     					   MemoryPoolHandle)) &BatchEncoder::decode,
     	 "Inverse of encode. This function 'unbatches' a given plaintext into a matrix \
         of integers modulo the plaintext modulus, and stores the result in the destination \
         parameter. The input plaintext must have degress less than the polynomial modulus, \
         and coefficients less than the plaintext modulus, i.e. it must be a valid plaintext \
         for the encryption parameters. Dynamic memory allocations in the process are \
         allocated from the memory pool pointed to by the given MemoryPoolHandle.",
    	 "plain"_a, "destination"_a, "pool"_a=MemoryManager::GetPool())
    .def("decode", (void (BatchEncoder::*)(const Plaintext &, std::vector<int64_t> &,
					   MemoryPoolHandle)) &BatchEncoder::decode,
	 "Inverse of encode. This function 'unbatches' a given plaintext into a matrix \
        of integers modulo the plaintext modulus, and stores the result in the destination \
        parameter. The input plaintext must have degress less than the polynomial modulus, \
        and coefficients less than the plaintext modulus, i.e. it must be a valid plaintext \
        for the encryption parameters. Dynamic memory allocations in the process are \
        allocated from the memory pool pointed to by the given MemoryPoolHandle.",
	 "plain"_a, "destination"_a, "pool"_a=MemoryManager::GetPool())
    .def("decode", (void (BatchEncoder::*)(Plaintext &, MemoryPoolHandle)) &BatchEncoder::decode,
	 "Inverse of encode. This function 'unbatches' a given plaintext in-place into \
        a matrix of integers modulo the plaintext modulus. The input plaintext must have \
        degress less than the polynomial modulus, and coefficients less than the plaintext \
        modulus, i.e. it must be a valid plaintext for the encryption parameters. Dynamic \
        memory allocations in the process are allocated from the memory pool pointed to by \
        the given MemoryPoolHandle.",
	 "plain"_a, "pool"_a=MemoryManager::GetPool())
    .def("slot_count", (std::size_t (BatchEncoder::*)()) &BatchEncoder::slot_count,
	 "Returns the number of slots");


  py::class_<CKKSEncoder>(m, "CKKSEncoder")
    .def(py::init<std::shared_ptr<SEALContext>>())
    .def("encode", (void (CKKSEncoder::*)(const std::vector<double> &, parms_id_type,
					  double, Plaintext &, MemoryPoolHandle)) &CKKSEncoder::encode,
	 "Encodes a vector of double-precision floating-point real or complex numbers \
        into a plaintext polynomial. Append zeros if vector size is less than N/2. \
        Dynamic memory allocations in the process are allocated from the memory \
        pool pointed to by the given MemoryPoolHandle.",
	 "values"_a, "parms_id"_a, "scale"_a, "destination"_a, "pool"_a=MemoryManager::GetPool())
    .def("encode", (void (CKKSEncoder::*)(const std::vector<std::complex<double>> &, parms_id_type,
					  double, Plaintext &, MemoryPoolHandle)) &CKKSEncoder::encode,
	 "Encodes a vector of double-precision floating-point real or complex numbers \
        into a plaintext polynomial. Append zeros if vector size is less than N/2. \
        Dynamic memory allocations in the process are allocated from the memory \
        pool pointed to by the given MemoryPoolHandle.",
	 "values"_a, "parms_id"_a, "scale"_a, "destination"_a, "pool"_a=MemoryManager::GetPool())
    .def("encode", (void (CKKSEncoder::*)(const std::vector<double> &, double,
					  Plaintext &, MemoryPoolHandle)) &CKKSEncoder::encode,
	 "Encodes a vector of double-precision floating-point real or complex numbers \
        into a plaintext polynomial. Append zeros if vector size is less than N/2. \
        The encryption parameters used are the top level parameters for the given \
        context. Dynamic memory allocations in the process are allocated from the \
        memory pool pointed to by the given MemoryPoolHandle.",
	 "values"_a, "scale"_a, "destination"_a, "pool"_a=MemoryManager::GetPool())
    .def("encode", (void (CKKSEncoder::*)(const std::vector<std::complex<double>> &, double,
					  Plaintext &, MemoryPoolHandle)) &CKKSEncoder::encode,
	 "Encodes a vector of double-precision floating-point real or complex numbers \
        into a plaintext polynomial. Append zeros if vector size is less than N/2. \
        The encryption parameters used are the top level parameters for the given \
        context. Dynamic memory allocations in the process are allocated from the \
        memory pool pointed to by the given MemoryPoolHandle.",
	 "values"_a, "scale"_a, "destination"_a, "pool"_a=MemoryManager::GetPool())
    .def("encode", (void (CKKSEncoder::*)(double, parms_id_type, double,
					  Plaintext &, MemoryPoolHandle)) &CKKSEncoder::encode,
	 "Encodes a double-precision floating-point real number into a plaintext \
        polynomial. The number repeats for N/2 times to fill all slots. Dynamic \
        memory allocations in the process are allocated from the memory pool \
        pointed to by the given MemoryPoolHandle.",
	 "value"_a, "parms_id"_a, "scale"_a, "destination"_a, "pool"_a=MemoryManager::GetPool())
    .def("encode", (void (CKKSEncoder::*)(double, double,
					  Plaintext &, MemoryPoolHandle)) &CKKSEncoder::encode,
	  "Encodes a double-precision floating-point real number into a plaintext \
        polynomial. The number repeats for N/2 times to fill all slots. The \
        encryption parameters used are the top level parameters for the given \
        context. Dynamic memory allocations in the process are allocated from \
        the memory pool pointed to by the given MemoryPoolHandle.",
	  "value"_a, "scale"_a, "destination"_a, "pool"_a=MemoryManager::GetPool())
    .def("encode", (void (CKKSEncoder::*)(std::complex<double>, parms_id_type, double,
					  Plaintext &, MemoryPoolHandle)) &CKKSEncoder::encode,
	 "Encodes a double-precision complex number into a plaintext polynomial. \
        Append zeros to fill all slots. Dynamic memory allocations in the process \
        are allocated from the memory pool pointed to by the given MemoryPoolHandle.",
	 "value"_a, "parms_id"_a, "scale"_a, "destination"_a, "pool"_a=MemoryManager::GetPool())
    .def("encode", (void (CKKSEncoder::*)(std::complex<double>, double,
					  Plaintext &, MemoryPoolHandle)) &CKKSEncoder::encode,
	 "Encodes a double-precision complex number into a plaintext polynomial. \
        Append zeros to fill all slots. The encryption parameters used are the \
        top level parameters for the given context. Dynamic memory allocations \
        in the process are allocated from the memory pool pointed to by the \
        given MemoryPoolHandle.",
	  "value"_a, "scale"_a, "destination"_a, "pool"_a=MemoryManager::GetPool())
    .def("encode", (void (CKKSEncoder::*)(std::int64_t, parms_id_type, Plaintext &)) &CKKSEncoder::encode,
	 "Encodes an integer number into a plaintext polynomial without any scaling. \
        The number repeats for N/2 times to fill all slots.",
	 "value"_a, "parms_id"_a, "destination"_a)
    .def("encode", (void (CKKSEncoder::*)(std::int64_t, Plaintext &)) &CKKSEncoder::encode,
	 "Encodes an integer number into a plaintext polynomial without any scaling. \
        The number repeats for N/2 times to fill all slots. The encryption \
        parameters used are the top level parameters for the given context.",
	 "value"_a, "destination"_a)
    .def("decode", (void (CKKSEncoder::*)(const Plaintext &, std::vector<double> &, 
					  MemoryPoolHandle)) &CKKSEncoder::decode,
	 "Decodes a plaintext polynomial into double-precision floating-point \
        real or complex numbers. Dynamic memory allocations in the process are \
        allocated from the memory pool pointed to by the given MemoryPoolHandle.",
	 "plain"_a, "destination"_a, "pool"_a=MemoryManager::GetPool())
    .def("decode", (void (CKKSEncoder::*)(const Plaintext &, std::vector<std::complex<double>> &, 
					  MemoryPoolHandle)) &CKKSEncoder::decode,
	 "Decodes a plaintext polynomial into double-precision floating-point \
        real or complex numbers. Dynamic memory allocations in the process are \
        allocated from the memory pool pointed to by the given MemoryPoolHandle.",
	 "plain"_a, "destination"_a, "pool"_a=MemoryManager::GetPool())
    .def("slot_count", (std::size_t (CKKSEncoder::*)()) &CKKSEncoder::slot_count,
	 "Returns the number of complex numbers encoded.");

}
