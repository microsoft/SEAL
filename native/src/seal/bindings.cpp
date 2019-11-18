#ifdef EMSCRIPTEN

#include <emscripten/bind.h>
#include <cstdint>
#include <stdexcept>
#include <iomanip>
#include <typeinfo>

#include "seal.h"

using namespace std;
using namespace emscripten;
using namespace seal;

// Many methods require a thin layer of C++ glue which is elegantly expressed with a lambda.
// However, passing a bare lambda into embind's daisy chain requires a cast to a function pointer.
#define EMBIND_LAMBDA(retval, arglist, impl) (retval (*) arglist) [] arglist impl

// Builder functions that return "this" have verbose binding declarations, this macro reduces
// the amount of boilerplate.
#define BUILDER_FUNCTION(name, btype, arglist, impl) \
        function(name, EMBIND_LAMBDA(btype*, arglist, impl), allow_raw_pointers())

/*
  Transform a JS TypedArray into a Vector of the appropriate type
*/
template<typename T>
std::vector<T> vecFromJSArray(const val &v) {
    std::vector<T> rv;
    const auto l = v["length"].as<unsigned>();
    rv.reserve(l);

    if (internal::typeSupportsMemoryView<T>()) {
        rv.resize(l);

        emscripten::val memoryView{emscripten::typed_memory_view(l, rv.data())};
        memoryView.call<void>("set", v);

        return rv;
    } else {
        for (unsigned i = 0; i < l; ++i) {
            rv.push_back(v[i].as<T>());
        }
    }

    return rv;
};

/*
  Get the underlying bytes from a Vector to a JS TypedArray.
*/
template<typename T>
emscripten::val jsArrayFromVec(const std::vector<T> &vec) {
    const auto length = vec.size();
    return val(typed_memory_view(length, vec.data()));
};

/*
Helper function: Prints a vector of floating-point values.
*/
template<typename T>
void printVector(std::vector<T> vec, size_t print_size = 4, int prec = 3)
{
    /*
    Save the formatting information for std::cout.
    */
    ios old_fmt(nullptr);
    old_fmt.copyfmt(cout);

    size_t slot_count = vec.size();

    cout << fixed << setprecision(prec) << endl;
    if(slot_count <= 2 * print_size)
    {
        cout << "    [";
        for (size_t i = 0; i < slot_count; i++)
        {
            cout << " " << vec[i] << ((i != slot_count - 1) ? "," : " ]\n");
        }
    }
    else
    {
        vec.resize(max(vec.size(), 2 * print_size));
        cout << "    [";
        for (size_t i = 0; i < print_size; i++)
        {
            cout << " " << vec[i] << ",";
        }
        if(vec.size() > 2 * print_size)
        {
            cout << " ...,";
        }
        for (size_t i = slot_count - print_size; i < slot_count; i++)
        {
            cout << " " << vec[i] << ((i != slot_count - 1) ? "," : " ]\n");
        }
    }
    cout << endl;

    /*
    Restore the old std::cout formatting.
    */
    cout.copyfmt(old_fmt);
}

/*
Printing the matrix is a bit of a pain.
*/
template<typename T>
void printMatrix(std::vector<T> &matrix, size_t row_size)
{
    /*
    Save the formatting information for std::cout.
    */
    ios old_fmt(nullptr);
    old_fmt.copyfmt(cout);

    cout << endl;

    /*
    We're not going to print every column of the matrix (there are 2048). Instead
    print this many slots from beginning and end of the matrix.
    */
    size_t print_size = 5;

    cout << "    [";
    for (size_t i = 0; i < print_size; i++)
    {
        cout << setw(3) << matrix[i] << ",";
    }
    cout << setw(3) << " ...,";
    for (size_t i = row_size - print_size; i < row_size; i++)
    {
        cout << setw(3) << matrix[i] << ((i != row_size - 1) ? "," : " ]\n");
    }
    cout << "    [";
    for (size_t i = row_size; i < row_size + print_size; i++)
    {
        cout << setw(3) << matrix[i] << ",";
    }
    cout << setw(3) << " ...,";
    for (size_t i = 2 * row_size - print_size; i < 2 * row_size; i++)
    {
        cout << setw(3) << matrix[i] << ((i != 2 * row_size - 1) ? "," : " ]\n");
    }
    cout << endl;

    /*
    Restore the old std::cout formatting.
    */
    cout.copyfmt(old_fmt);
}

/*
Helper function: Prints the parameters in a SEALContext.
*/
void printContext(shared_ptr<SEALContext> context)
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

/*
 Gets the exception string from the thrown pointer
*/
std::string get_exception(intptr_t ptr) {
  auto exception = reinterpret_cast<std::exception *>(ptr);
  std::string error_string = exception->what();
  return error_string;
}

EMSCRIPTEN_BINDINGS(bindings)
{
    emscripten::function("getException", &get_exception);
    emscripten::function("printContext", &printContext);
    emscripten::function("jsArrayInt32FromVec", select_overload<val(const std::vector<int32_t> &)>(&jsArrayFromVec));
    emscripten::function("jsArrayUint32FromVec", select_overload<val(const std::vector<uint32_t> &)>(&jsArrayFromVec));
    emscripten::function("jsArrayDoubleFromVec", select_overload<val(const std::vector<double> &)>(&jsArrayFromVec));

    emscripten::function("vecFromArrayInt32", select_overload<std::vector<int32_t>(const val &)>(&vecFromJSArray));
    emscripten::function("vecFromArrayUInt32", select_overload<std::vector<uint32_t>(const val &)>(&vecFromJSArray));
//    emscripten::function("vecFromArrayInt64", select_overload<std::vector<int64_t>(const val &)>(&vecFromJSArray));
//    emscripten::function("vecFromArrayUInt64", select_overload<std::vector<uint64_t>(const val &)>(&vecFromJSArray));
    emscripten::function("vecFromArrayDouble", select_overload<std::vector<double>(const val &)>(&vecFromJSArray));
    emscripten::function("printVectorInt32", select_overload<void(std::vector<int32_t>, size_t, int)>(&printVector));
    emscripten::function("printVectorUInt32", select_overload<void(std::vector<uint32_t>, size_t, int)>(&printVector));
//    emscripten::function("printVectorInt64", select_overload<void(std::vector<int64_t>, size_t, int)>(&printVector));
//    emscripten::function("printVectorUInt64", select_overload<void(std::vector<uint64_t>, size_t, int)>(&printVector));
    emscripten::function("printVectorDouble", select_overload<void(std::vector<double>, size_t, int)>(&printVector));
//    emscripten::function("printVectorComplexDouble", select_overload<void(std::vector<std::complex<double>>, size_t, int)>(&printVector));
    emscripten::function("printMatrixInt32", select_overload<void(std::vector<int32_t> &, size_t)>(&printMatrix));
    emscripten::function("printMatrixUInt32", select_overload<void(std::vector<uint32_t> &, size_t)>(&printMatrix));

    register_vector<SmallModulus>("std::vector<SmallModulus>");
    register_vector<Ciphertext>("std::vector<Ciphertext>");
    register_vector<int32_t>("std::vector<int32_t>");
    register_vector<uint32_t>("std::vector<uint32_t>");
//    register_vector<int64_t>("std::vector<int64_t>");
//    register_vector<uint64_t>("std::vector<uint64_t>");
    register_vector<double>("std::vector<double>");
    register_vector<std::complex<double>>("std::vector<std::complex<double>>");

    // TODO: Finish defining this item as it just returns an empty array in the JS side
    // using sha3_block_type = std::array<std::uint64_t, sha3_block_uint64_count>;
    value_array<parms_id_type>("parms_id_type");

    class_<util::HashFunction>("util::HashFunction")
        .class_property("hash_block_uint64_count", &util::HashFunction::hash_block_uint64_count)
        .class_property("hash_block_byte_count", &util::HashFunction::hash_block_byte_count)
        .class_function("hash", &util::HashFunction::hash, allow_raw_pointers())
      ;

    enum_<sec_level_type>("SecLevelType")
        .value("none", sec_level_type::none)
        .value("tc128", sec_level_type::tc128)
        .value("tc192", sec_level_type::tc192)
        .value("tc256", sec_level_type::tc256)
        ;

    class_<CoeffModulus>("CoeffModulus")
        .class_function("MaxBitCount", &CoeffModulus::MaxBitCount)
        .class_function("BFVDefault", &CoeffModulus::BFVDefault)
        .class_function("Create", &CoeffModulus::Create)
        ;

    class_<PlainModulus>("PlainModulus")
        .class_function("Batching", select_overload<SmallModulus(std::size_t, int)>(&PlainModulus::Batching))
        .class_function("BatchingVector", select_overload<std::vector<SmallModulus>(std::size_t, std::vector<int>)>(&PlainModulus::Batching))
        ;

    class_<SmallModulus>("SmallModulus")
        .constructor<>()
        .function("isZero", &SmallModulus::is_zero)
        .function("isPrime", &SmallModulus::is_prime)
        .function("bitCount", &SmallModulus::bit_count)
        .function("value", &SmallModulus::Value)
        .function("loadFromString", &SmallModulus::LoadFromString)
        .function("saveToString", &SmallModulus::SaveToString)
        .function("createFromString", &SmallModulus::CreateFromString)
        ;

    class_<EncryptionParameters>("EncryptionParameters")
        .constructor<scheme_type>()
        .function("setPolyModulusDegree", &EncryptionParameters::set_poly_modulus_degree)
        .function("setCoeffModulus", &EncryptionParameters::set_coeff_modulus)
        .function("setPlainModulus", select_overload<void(const SmallModulus &)>(&EncryptionParameters::set_plain_modulus))
        .function("scheme", &EncryptionParameters::scheme)
        .function("polyModulusDegree", &EncryptionParameters::poly_modulus_degree)
        .function("coeffModulus", &EncryptionParameters::coeff_modulus)
        .function("plainModulus", &EncryptionParameters::plain_modulus)
        .class_function("saveToString", &EncryptionParameters::SaveToString)
        .class_function("createFromString", &EncryptionParameters::CreateFromString)
        ;

    class_<EncryptionParameterQualifiers>("EncryptionParameterQualifiers")
        .property("parametersSet", &EncryptionParameterQualifiers::parameters_set)
        .property("usingFFT", &EncryptionParameterQualifiers::using_fft)
        .property("usingNTT", &EncryptionParameterQualifiers::using_ntt)
        .property("usingBatching", &EncryptionParameterQualifiers::using_batching)
        .property("usingFastPlainLift", &EncryptionParameterQualifiers::using_fast_plain_lift)
        .property("usingDescendingModulusChain", &EncryptionParameterQualifiers::using_descending_modulus_chain)
        .property("securityLevel", &EncryptionParameterQualifiers::sec_level)
        ;

    class_<SEALContext::ContextData>("SEALContext::ContextData")
        .smart_ptr<std::shared_ptr<SEALContext::ContextData>>("std::shared_ptr<SEALContext::ContextData>")
        .function("parms", &SEALContext::ContextData::parms)
        .function("parmsId", &SEALContext::ContextData::parms_id)
        .function("qualifiers", &SEALContext::ContextData::qualifiers)
        .function("totalCoeffModulus", &SEALContext::ContextData::total_coeff_modulus, allow_raw_pointers())
        .function("totalCoeffModulusBitCount", &SEALContext::ContextData::total_coeff_modulus_bit_count)
//        .function("baseConverter", &SEALContext::ContextData::base_converter)
//        .function("smallNttTables", &SEALContext::ContextData::small_ntt_tables)
//        .function("plainNttTables", &SEALContext::ContextData::plain_ntt_tables)
        .function("coeffDivPlainModulus", &SEALContext::ContextData::coeff_div_plain_modulus, allow_raw_pointers())
        .function("plainUpperHalfThreshold", &SEALContext::ContextData::plain_upper_half_threshold, allow_raw_pointers())
        .function("plainUpperHalfIncrement", &SEALContext::ContextData::plain_upper_half_increment, allow_raw_pointers())
        .function("upperHalfThreshold", &SEALContext::ContextData::upper_half_threshold, allow_raw_pointers())
        .function("upperHalfIncrement", &SEALContext::ContextData::upper_half_increment, allow_raw_pointers())
        .function("coeffModPlainModulus", &SEALContext::ContextData::coeff_mod_plain_modulus)
        .function("prevContextData", &SEALContext::ContextData::prev_context_data)
        .function("nextContextData", &SEALContext::ContextData::next_context_data)
        .function("chainIndex", &SEALContext::ContextData::chain_index)
        ;

    class_<SEALContext>("SEALContext")
        .smart_ptr_constructor("std::shared_ptr<SEALContext>", &SEALContext::Create)
//        These two work below:
//        .smart_ptr<std::shared_ptr<SEALContext>>("std::shared_ptr<SEALContext>")
//        .constructor(&SEALContext::Create)
//
//        .smart_ptr<std::shared_ptr<SEALContext>>("&SEALContext::first_context_data")
//        .smart_ptr<std::shared_ptr<SEALContext>>("&SEALContext::first_context_data")
//        .smart_ptr_constructor("firstContextData", &SEALContext::first_context_data)
        .function("getContextData", &SEALContext::get_context_data)
        .function("keyContextData", &SEALContext::key_context_data)
        .function("firstContextData", &SEALContext::first_context_data)
        .function("lastContextData", &SEALContext::last_context_data)
        .function("parametersSet", &SEALContext::parameters_set)
        .function("keyParmsId", &SEALContext::key_parms_id)
        .function("firstParmsId", &SEALContext::first_parms_id)
        .function("lastParmsId", &SEALContext::last_parms_id)
        .function("usingKeyswitching", &SEALContext::using_keyswitching)
        ;

    class_<Evaluator>("Evaluator")
        .constructor<std::shared_ptr<SEALContext>>()
        .function("negate", &Evaluator::negate)
        .function("add", &Evaluator::add)
        .function("sub", &Evaluator::sub)
        .function("multiply", &Evaluator::multiply)
        .function("square", &Evaluator::square)
        .function("relinearize", &Evaluator::relinearize)
        .function("cipherModSwitchToNext", select_overload<void(const Ciphertext &, Ciphertext &, MemoryPoolHandle)>(&Evaluator::mod_switch_to_next))
        .function("cipherModSwitchTo", select_overload<void(const Ciphertext &, parms_id_type, Ciphertext &, MemoryPoolHandle)>(&Evaluator::mod_switch_to))
        .function("plainModSwitchToNext", select_overload<void(const Plaintext &, Plaintext &)>(&Evaluator::mod_switch_to_next))
        .function("plainModSwitchTo", select_overload<void(const Plaintext &, parms_id_type, Plaintext &)>(&Evaluator::mod_switch_to))
        .function("rescaleToNext", &Evaluator::rescale_to_next)
        .function("rescaleTo", &Evaluator::rescale_to)
        .function("exponentiate", &Evaluator::exponentiate_unsafe_cast)
        .function("addPlain", &Evaluator::add_plain)
        .function("subPlain", &Evaluator::sub_plain)
        .function("multiplyPlain", &Evaluator::multiply_plain)
        .function("plainTransformToNtt", select_overload<void(const Plaintext &, parms_id_type, Plaintext &, MemoryPoolHandle)>(&Evaluator::transform_to_ntt))
        .function("cipherTransformToNtt", select_overload<void(const Ciphertext &, Ciphertext &)>(&Evaluator::transform_to_ntt))
        .function("cipherTransformFromNtt", select_overload<void(const Ciphertext &, Ciphertext &)>(&Evaluator::transform_from_ntt))
        .function("applyGalois", &Evaluator::apply_galois)
        .function("rotateRows", &Evaluator::rotate_rows)
        .function("rotateColumns", &Evaluator::rotate_columns)
        .function("rotateVector", &Evaluator::rotate_vector)
        .function("complexConjugate", &Evaluator::complex_conjugate)
        ;

    class_<KSwitchKeys>("KSwitchKeys")
        .constructor<>()
        .function("saveToString", &KSwitchKeys::SaveToString)
        .function("loadFromString", &KSwitchKeys::LoadFromString)
        ;

    class_<RelinKeys, base<KSwitchKeys>>("RelinKeys")
        .constructor<>()
        ;
    class_<GaloisKeys, base<KSwitchKeys>>("GaloisKeys")
        .constructor<>()
        ;

    class_<KeyGenerator>("KeyGenerator")
        .constructor<std::shared_ptr<SEALContext>>()
        .constructor<std::shared_ptr<SEALContext>, const SecretKey &>()
        .constructor<std::shared_ptr<SEALContext>, const SecretKey &, const PublicKey &>()
        .function("getPublicKey", &KeyGenerator::public_key)
        .function("getSecretKey", &KeyGenerator::secret_key)
        .function("createRelinKeys", select_overload<RelinKeys()>(&KeyGenerator::relin_keys))
        .function("createGaloisKeys", select_overload<GaloisKeys()>(&KeyGenerator::galois_keys))
        ;

    class_<PublicKey>("PublicKey")
        .constructor<>()
        .function("saveToString", &PublicKey::SaveToString)
        .function("loadFromString", &PublicKey::LoadFromString)
        ;

    class_<SecretKey>("SecretKey")
        .constructor<>()
        .function("saveToString", &SecretKey::SaveToString)
        .function("loadFromString", &SecretKey::LoadFromString)
        ;

    class_<Plaintext>("Plaintext")
        .constructor<>()
        .function("saveToString", &Plaintext::SaveToString)
        .function("loadFromString", &Plaintext::LoadFromString)
        .function("shrinkToFit", &Plaintext::shrink_to_fit)
        .function("isZero", &Plaintext::is_zero)
        .function("capacity", &Plaintext::capacity)
        .function("coeffCount", &Plaintext::coeff_count)
        .function("significantCoeffCount", &Plaintext::significant_coeff_count)
        .function("nonzeroCoeffCount", &Plaintext::nonzero_coeff_count)
        .function("toPolynomial", &Plaintext::to_string)
        .function("isNttForm", select_overload< bool () const>(&Plaintext::is_ntt_form))
        .function("parmsId", select_overload< parms_id_type & ()>(&Plaintext::parms_id))
        .function("scale", select_overload< double & ()>(&Plaintext::scale))
        .function("pool", &Plaintext::pool)
        ;

    class_<Ciphertext>("Ciphertext")
        .constructor<>()
        .function("saveToString", &Ciphertext::SaveToString)
        .function("loadFromString", &Ciphertext::LoadFromString)
        .function("coeffModCount", &Ciphertext::coeff_mod_count)
        .function("polyModulusDegree", &Ciphertext::poly_modulus_degree)
        .function("size", &Ciphertext::size)
        .function("sizeCapacity", &Ciphertext::size_capacity)
        .function("isTransparent", &Ciphertext::is_transparent)
        .function("isNttForm", select_overload< bool () const>(&Ciphertext::is_ntt_form))
        .function("parmsId", select_overload< parms_id_type & ()>(&Ciphertext::parms_id))
        .function("scale", select_overload< double & ()>(&Ciphertext::scale))
        .function("pool", &Ciphertext::pool)
        ;

    class_<IntegerEncoder>("IntegerEncoder")
        .constructor<std::shared_ptr<SEALContext>>()
        .function("encodeInt32", select_overload<Plaintext(std::int32_t)>(&IntegerEncoder::encode))
        .function("encodeUInt32", select_overload<Plaintext(std::uint32_t)>(&IntegerEncoder::encode))
        .function("decodeInt32", select_overload<std::int32_t(const Plaintext &)>(&IntegerEncoder::decode_int32))
        .function("decodeUInt32", select_overload<std::uint32_t(const Plaintext &)>(&IntegerEncoder::decode_uint32))
//        .function("encodeInt64", select_overload<Plaintext(std::int64_t)>(&IntegerEncoder::encode))
//        .function("encodeUInt64", select_overload<Plaintext(std::uint64_t)>(&IntegerEncoder::encode))
//        .function("encodeBigUInt", select_overload<Plaintext(const BigUInt &)>(&IntegerEncoder::encode))
//        .function("decodeInt64", select_overload<std::int64_t(const Plaintext &)>(&IntegerEncoder::decode_int64))
//        .function("decodeUInt64", select_overload<std::uint64_t(const Plaintext &)>(&IntegerEncoder::decode_uint64))
//        .function("decodeBigUInt", select_overload<BigUInt(const Plaintext &)>(&IntegerEncoder::decode_biguint))
        ;

    class_<BatchEncoder>("BatchEncoder")
        .constructor<std::shared_ptr<SEALContext>>()
        .function("encodeVectorInt32", select_overload<void(const std::vector<std::int32_t> &, Plaintext &)>(&BatchEncoder::encodeVector))
        .function("encodeVectorUInt32", select_overload<void(const std::vector<std::uint32_t> &, Plaintext &)>(&BatchEncoder::encodeVector))
        .function("decodeVectorInt32", select_overload<void(const Plaintext &, std::vector<std::int32_t> &, MemoryPoolHandle)>(&BatchEncoder::decodeVector))
        .function("decodeVectorUInt32", select_overload<void(const Plaintext &, std::vector<std::uint32_t> &, MemoryPoolHandle)>(&BatchEncoder::decodeVector))
        .function("slotCount", &BatchEncoder::slot_count)
        ;

    class_<CKKSEncoder>("CKKSEncoder")
        .constructor<std::shared_ptr<SEALContext>>()
        .function("encodeVectorDouble", select_overload<void(const std::vector<double> &, double, Plaintext &, MemoryPoolHandle)>(&CKKSEncoder::encodeVector))
//        .function("encodeVectorComplexDouble", select_overload<void(const std::vector<std::complex<double>> &, double, Plaintext &, MemoryPoolHandle)>(&CKKSEncoder::encodeVector))
        .function("decodeVectorDouble", select_overload<void(const Plaintext &, std::vector<double> &, MemoryPoolHandle)>(&CKKSEncoder::decodeVector))
//        .function("decodeVectorComplexDouble", select_overload<void(const Plaintext &, std::vector<std::complex<double>> &, MemoryPoolHandle)>(&CKKSEncoder::decodeVector))
        .function("slotCount", &CKKSEncoder::slot_count)
        ;

    class_<MemoryPoolHandle>("MemoryPoolHandle")
        .constructor<>()
        .class_function("MemoryPoolHandleGlobal", &MemoryPoolHandle::Global)
        .class_function("MemoryPoolHandleThreadLocal", &MemoryPoolHandle::ThreadLocal)
        .class_function("MemoryPoolHandleNew", &MemoryPoolHandle::New)
        ;

    class_<MemoryManager>("MemoryManager")
        .function("GetPool", select_overload<MemoryPoolHandle(mm_prof_opt_t)>(&MemoryManager::GetPool))
        ;

    class_<MMProf>("MMProf")
        ;

    class_<MMProfGlobal, base<MMProf>>("MMProfGlobal")
        .function("getPool", &MMProfGlobal::get_pool)
        ;

    class_<MMProfNew, base<MMProf>>("MMProfNew")
        .function("getPool", &MMProfNew::get_pool)
        ;

    class_<MMProfFixed, base<MMProf>>("MMProfFixed")
        .function("getPool", &MMProfFixed::get_pool)
        ;

    class_<MMProfThreadLocal, base<MMProf>>("MMProfThreadLocal")
        .function("getPool", &MMProfThreadLocal::get_pool)
        ;

    class_<Encryptor>("Encryptor")
        .constructor<std::shared_ptr<SEALContext>, const PublicKey &>()
        .constructor<std::shared_ptr<SEALContext>, const PublicKey &, const SecretKey &>() // embind caveat, have to use this overload as the contructor for symmetric encryption
        .function("setPublicKey", &Encryptor::set_public_key)
        .function("setSecretKey", &Encryptor::set_secret_key)
        .function("encrypt", &Encryptor::encrypt)
        .function("encryptSymmetric", &Encryptor::encrypt_symmetric)
        ;

    class_<Decryptor>("Decryptor")
        .constructor<std::shared_ptr<SEALContext>, const SecretKey &>()
        .function("decrypt", &Decryptor::decrypt)
        .function("invariantNoiseBudget", &Decryptor::invariant_noise_budget)
        ;

    enum_<scheme_type>("SchemeType")
        .value("none", scheme_type::none)
        .value("BFV", scheme_type::BFV)
        .value("CKKS", scheme_type::CKKS)
        ;

    //enum_<mm_prof_opt>("mm_prof_opt")
    //    .value("DEFAULT", mm_prof_opt::DEFAULT)
    //    .value("FORCE_GLOBAL", mm_prof_opt::FORCE_GLOBAL)
    //    .value("FORCE_NEW", mm_prof_opt::FORCE_NEW)
    //    .value("FORCE_THREAD_LOCAL", mm_prof_opt::FORCE_THREAD_LOCAL)
    //    ;
}

#endif
