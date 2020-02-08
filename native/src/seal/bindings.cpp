#ifdef EMSCRIPTEN

#include<emscripten/bind.h>
#include<cstdint>
#include<stdexcept>
#include<iomanip>
#include<typeinfo>
#include "base64.h"
#include "seal.h"

using namespace std;
using namespace emscripten;
using namespace seal;

/*
  Transform a JS TypedArray into a Vector of the appropriate type
*/
template<typename T>
    std::vector<T> vecFromJSArray(const val &v) {
        std::vector<T> rv;
        const auto l = v["length"].as<unsigned>();
        rv.reserve(l);
        rv.resize(l);

        emscripten::val memoryView {
            emscripten::typed_memory_view(l, rv.data())
        };
        memoryView.call<void>("set", v);

        return rv;
    };

/*
  Get the underlying bytes from a Vector to a JS TypedArray.
*/
template<typename T>
    emscripten::val jsArrayFromVec(const std::vector<T>  &vec) {
        const auto length = vec.size();
        return val(typed_memory_view(length, vec.data()));
    };

/*
  Converts a Vector of type T1 to type T2
*/
template<typename T1, typename T2>
    void convert_vector(const std::vector<T1> &vector_input, std::vector<T2> &vector_output) {
        std::copy(vector_input.begin(), vector_input.end(), std::back_inserter(vector_output));
    }

/*
Helper function: Prints a vector of floating-point values.
*/
template<typename T>
    void printVector(std::vector<T> vec, size_t print_size = 4, int prec = 3) {
        /*
        Save the formatting information for std::cout.
        */
        ios old_fmt(nullptr);
        old_fmt.copyfmt(cout);

        size_t slot_count = vec.size();

        cout << fixed << setprecision(prec) << endl;
        if (slot_count<= 2 *print_size) {
            cout << "    [";
            for (size_t i = 0; i<slot_count; i++) {
                cout << " " << vec[i] << ((i != slot_count - 1) ? "," : " ]\n");
            }
        } else {
            vec.resize(max(vec.size(), 2 *print_size));
            cout << "    [";
            for (size_t i = 0; i<print_size; i++) {
                cout << " " << vec[i] << ",";
            }
            if (vec.size()>2 *print_size) {
                cout << " ...,";
            }
            for (size_t i = slot_count - print_size; i<slot_count; i++) {
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
    void printMatrix(std::vector<T>  &matrix, size_t row_size) {
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
        for (size_t i = 0; i<print_size; i++) {
            cout << setw(3) << matrix[i] << ",";
        }
        cout << setw(3) << " ...,";
        for (size_t i = row_size - print_size; i<row_size; i++) {
            cout << setw(3) << matrix[i] << ((i != row_size - 1) ? "," : " ]\n");
        }
        cout << "    [";
        for (size_t i = row_size; i<row_size + print_size; i++) {
            cout << setw(3) << matrix[i] << ",";
        }
        cout << setw(3) << " ...,";
        for (size_t i = 2 *row_size - print_size; i<2 *row_size; i++) {
            cout << setw(3) << matrix[i] << ((i != 2 *row_size - 1) ? "," : " ]\n");
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
void printContext(shared_ptr<SEALContext> context) {
    // Verify parameters
    if (!context) {
        throw std::invalid_argument("context is not set");
    }
    auto &context_data = *context->key_context_data();

    /*
    Which scheme are we using?
    */
    std::string scheme_name;
    switch (context_data.parms().scheme()) {
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
    for (std::size_t i = 0; i < coeff_mod_count - 1; i++) {
        std::cout << coeff_modulus[i].bit_count() << " + ";
    }
    std::cout << coeff_modulus.back().bit_count();
    std::cout << ") bits" << std::endl;

    /*
    For the BFV scheme print the plain_modulus parameter.
    */
    if (context_data.parms().scheme() == seal::scheme_type::BFV) {
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

EMSCRIPTEN_BINDINGS(bindings) {
    emscripten:: function ("getException", &get_exception);
    emscripten:: function ("printContext", &printContext);
    emscripten:: function ("jsArrayInt32FromVec", select_overload<val(const std::vector<int32_t> &)>(&jsArrayFromVec));
    emscripten:: function ("jsArrayUint32FromVec", select_overload<val(const std::vector<uint32_t> &)>(&jsArrayFromVec));
    emscripten:: function ("jsArrayDoubleFromVec", select_overload<val(const std::vector<double> &)>(&jsArrayFromVec));
    emscripten:: function ("vecFromArrayInt32", select_overload<std::vector<int32_t>(const val &)>(&vecFromJSArray));
    emscripten:: function ("vecFromArrayUInt32", select_overload<std::vector<uint32_t>(const val &)>(&vecFromJSArray));
    emscripten:: function ("vecFromArrayDouble", select_overload<std::vector<double>(const val &)>(&vecFromJSArray));
    emscripten:: function ("printVectorInt32", select_overload<void(std::vector<int32_t>, size_t, int)>(&printVector));
    emscripten:: function ("printVectorUInt32", select_overload<void(std::vector<uint32_t>, size_t, int)>(&printVector));
    emscripten:: function ("printVectorDouble", select_overload<void(std::vector<double>, size_t, int)>(&printVector));
    emscripten:: function ("printMatrixInt32", select_overload<void(std::vector<int32_t> &, size_t)>(&printMatrix));
    emscripten:: function ("printMatrixUInt32", select_overload<void(std::vector<uint32_t> &, size_t)>(&printMatrix));

    register_vector<Ciphertext>("std::vector<Ciphertext>");
    register_vector<int32_t>("std::vector<int32_t>");
    register_vector<uint32_t>("std::vector<uint32_t>");
    register_vector<double>("std::vector<double>");
    register_vector<std::complex<double>> ("std::vector<std::complex<double>>");

    class_<std::vector<SmallModulus>> ("std::vector<SmallModulus>")
        .constructor<>()
        .function("values", optional_override([](std::vector<SmallModulus> &self) {
            std::ostringstream str;
            std::string separator;
            for (auto x: self) {
                str << separator << x.value();
                separator = ',';
            }
            return str.str();
        }));

    class_<util::HashFunction>("util::HashFunction")
        .class_property("hashBlockUint64Count", &util::HashFunction::hash_block_uint64_count)
        .class_property("hashBlockByteCount", &util::HashFunction::hash_block_byte_count)
        .class_function("hash", &util::HashFunction::hash, allow_raw_pointers());

    // using parms_id_type = util::HashFunction::hash_block_type
    // using hash_block_type std::array<std::uint64_t, hash_block_uint64_count>;

    class_<parms_id_type>("ParmsIdType")
        .constructor<>()
        .function("values", optional_override([](parms_id_type &self) {
            std::ostringstream str;
            std::string separator;
            for (auto x: self) {
                str << separator << x;
                separator = ',';
            }
            return str.str();
        }));

    enum_<sec_level_type>("SecLevelType")
        .value("none", sec_level_type::none)
        .value("tc128", sec_level_type::tc128)
        .value("tc192", sec_level_type::tc192)
        .value("tc256", sec_level_type::tc256);

    enum_<compr_mode_type>("ComprModeType")
        .value("none", compr_mode_type::none)
#ifdef SEAL_USE_ZLIB
        .value("deflate", compr_mode_type::deflate)
#endif
        ;

    class_<CoeffModulus>("CoeffModulus")
        .class_function("MaxBitCount", &CoeffModulus::MaxBitCount)
        .class_function("BFVDefault", &CoeffModulus::BFVDefault)
        .class_function("Create", &CoeffModulus::Create)
        .class_function("CreateFromArray", optional_override([](const std::size_t &poly_modulus_degree,
            const val &v) {
            std::vector<int>bit_sizes;
            const auto l = v["length"].as<unsigned>();
            bit_sizes.resize(l);
            val memoryView {
                typed_memory_view(l, bit_sizes.data())
            };
            memoryView.call<void>("set", v);
            std::vector<SmallModulus>coeffModulus = CoeffModulus::Create(poly_modulus_degree, bit_sizes);
            return coeffModulus;
        }));
    class_<PlainModulus>("PlainModulus")
        .class_function("Batching", select_overload<SmallModulus(std::size_t, int)>(&PlainModulus::Batching))
        .class_function("BatchingVector", select_overload<std::vector<SmallModulus>(std::size_t, std::vector<int>)>(&PlainModulus::Batching));

    class_<SmallModulus>("SmallModulus")
        .constructor<>()
        .function("isZero", optional_override([](SmallModulus &self) {
            return self.is_zero();
        }))
        .function("isPrime", optional_override([](SmallModulus &self) {
            return self.is_prime();
        }))
        .function("bitCount", optional_override([](SmallModulus &self) {
            return self.bit_count();
        }))
        .function("saveToString", optional_override([](SmallModulus &self,
            compr_mode_type compr_mode) {
            std::ostringstream buffer;
            self.save(buffer, compr_mode);
            std::string contents = buffer.str();
            std::string encoded = b64encode(contents);
            return encoded;
        }))
        .function("loadFromString", optional_override([](SmallModulus &self,
            const std::string &encoded) {
            std::string decoded = b64decode(encoded);
            std::istringstream is(decoded);
            self.load(is);
        }))
        .function("createFromString", optional_override([](SmallModulus &self,
            const std::string &encoded) {
            std::string decoded = b64decode(encoded);
            std::istringstream is(decoded);
            SmallModulus sm;
            sm.load(is);
            return sm;
        }))
        .function("value", optional_override([](SmallModulus &self) {
            uint64_t value;
            value = self.value();
            std::ostringstream oss;
            oss << value;
            std::string intAsString;
            intAsString = oss.str();
            return intAsString;
        }));

    class_<EncryptionParameters>("EncryptionParameters")
        .constructor<scheme_type>()
        .function("setPolyModulusDegree", &EncryptionParameters::set_poly_modulus_degree)
        .function("setCoeffModulus", &EncryptionParameters::set_coeff_modulus)
        .function("setPlainModulus", select_overload<void(const SmallModulus &)>(&EncryptionParameters::set_plain_modulus))
        .function("scheme", optional_override([](EncryptionParameters &self) {
            return self.scheme();
        }))
        .function("polyModulusDegree", optional_override([](EncryptionParameters &self) {
            return self.poly_modulus_degree();
        }))
        .function("coeffModulus", optional_override([](EncryptionParameters &self) {
            return self.coeff_modulus();
        }))
        .function("plainModulus", optional_override([](EncryptionParameters &self) {
            return self.plain_modulus();
        }))
        .function("saveToString", optional_override([](EncryptionParameters &self,
            compr_mode_type compr_mode) {
            std::ostringstream buffer;
            self.save(buffer, compr_mode);
            std::string contents = buffer.str();
            std::string encoded = b64encode(contents);
            return encoded;
        }))
        .function("loadFromString", optional_override([](EncryptionParameters &self,
            const std::string &encoded) {
            std::string decoded = b64decode(encoded);
            std::istringstream is(decoded);
            self.load(is);
        }));

    class_<EncryptionParameterQualifiers>("EncryptionParameterQualifiers")
        .property("parametersSet", &EncryptionParameterQualifiers::parameters_set)
        .property("usingFFT", &EncryptionParameterQualifiers::using_fft)
        .property("usingNTT", &EncryptionParameterQualifiers::using_ntt)
        .property("usingBatching", &EncryptionParameterQualifiers::using_batching)
        .property("usingFastPlainLift", &EncryptionParameterQualifiers::using_fast_plain_lift)
        .property("usingDescendingModulusChain", &EncryptionParameterQualifiers::using_descending_modulus_chain)
        .property("securityLevel", &EncryptionParameterQualifiers::sec_level);

    class_<std::shared_ptr<const SEALContext::ContextData>> ("ContextData")
        .function("parms", optional_override([](std::shared_ptr<
            const SEALContext::ContextData> &self) {
            return self->parms(); // Returns a pointer to EncryptionParameters
        }))
        .function("parmsId", optional_override([](std::shared_ptr<
            const SEALContext::ContextData> &self) {
            return self->parms_id(); // Returns a pointer to ParmsIdType
        }))
        .function("qualifiers", optional_override([](std::shared_ptr<
            const SEALContext::ContextData> &self) {
            return self->qualifiers(); // Returns a pointer to EncryptionParameterQualifiers
        }))
        //        .function("totalCoeffModulus", optional_override([](std::shared_ptr<const SEALContext::ContextData> &self) {
        //               return self->total_coeff_modulus();
        //          }), allow_raw_pointers())
        .function("totalCoeffModulusBitCount", optional_override([](std::shared_ptr<
            const SEALContext::ContextData> &self) {
            return self->total_coeff_modulus_bit_count();
        }))
        //        .function("coeffDivPlainModulus", optional_override([](std::shared_ptr<const SEALContext::ContextData> &self) {
        //               return self->coeff_div_plain_modulus();
        //          }), allow_raw_pointers())
        //        .function("baseConverter", &SEALContext::ContextData::base_converter)
        //        .function("smallNttTables", &SEALContext::ContextData::small_ntt_tables)
        //        .function("plainNttTables", &SEALContext::ContextData::plain_ntt_tables)
        //        .function("plainUpperHalfThreshold", optional_override([](std::shared_ptr<const SEALContext::ContextData> &self) {
        //               return self->plain_upper_half_threshold();
        //          }), allow_raw_pointers())
        //        .function("plainUpperHalfIncrement", optional_override([](std::shared_ptr<const SEALContext::ContextData> &self) {
        //               return self->plain_upper_half_increment();
        //          }), allow_raw_pointers())
        //        .function("upperHalfThreshold", optional_override([](std::shared_ptr<const SEALContext::ContextData> &self) {
        //               return self->upper_half_threshold();
        //          }), allow_raw_pointers())
        //        .function("upperHalfIncrement", optional_override([](std::shared_ptr<const SEALContext::ContextData> &self) {
        //               return self->upper_half_increment();
        //          }), allow_raw_pointers())
        //        .function("coeffModPlainModulus", optional_override([](std::shared_ptr<const SEALContext::ContextData> &self) {
        //               return self->coeff_mod_plain_modulus();
        //          }))
        .function("prevContextData", optional_override([](std::shared_ptr<
            const SEALContext::ContextData> &self) {
            return self->prev_context_data(); // Returns a pointer to ContextData
        }))
        .function("nextContextData", optional_override([](std::shared_ptr<
            const SEALContext::ContextData> &self) {
            return self->next_context_data(); // Returns a pointer to ContextData
        }))
        .function("chainIndex", optional_override([](std::shared_ptr<
            const SEALContext::ContextData> &self) {
            return self->chain_index();
        }));

    class_<SEALContext>("SEALContext")
        .smart_ptr_constructor("std::shared_ptr<SEALContext>", &SEALContext::Create)
        .function("getContextData", &SEALContext::get_context_data)
        .function("keyContextData", &SEALContext::key_context_data)
        .function("firstContextData", &SEALContext::first_context_data)
        .function("lastContextData", &SEALContext::last_context_data)
        .function("parametersSet", &SEALContext::parameters_set)
        .function("keyParmsId", optional_override([](SEALContext &self) {
            return self.key_parms_id();
        }))
        .function("firstParmsId", optional_override([](SEALContext &self) {
            return self.first_parms_id();
        }))
        .function("lastParmsId", optional_override([](SEALContext &self) {
            return self.last_parms_id();
        }))
        .function("usingKeyswitching", optional_override([](SEALContext &self) {
            return self.using_keyswitching();
        }));

    class_<Evaluator>("Evaluator")
        .constructor<std::shared_ptr<SEALContext>> ()
        .function("negate", &Evaluator::negate)
        .function("add", &Evaluator::add)
        .function("addPlain", &Evaluator::add_plain)
        .function("sub", &Evaluator::sub)
        .function("subPlain", &Evaluator::sub_plain)
        .function("multiply", &Evaluator::multiply)
        .function("multiplyPlain", &Evaluator::multiply_plain)
        .function("square", &Evaluator::square)
        .function("exponentiate", optional_override([](Evaluator &self,
            const Ciphertext &encrypted, std::uint32_t exponent,
            const RelinKeys &relin_keys, Ciphertext &destination,
            MemoryPoolHandle pool = MemoryManager::GetPool()) {
            std::uint64_t exponent_uint64 = (uint64_t) exponent;
            return self.Evaluator::exponentiate(encrypted, exponent_uint64, relin_keys, destination, pool);
        }))
        .function("relinearize", &Evaluator::relinearize)
        .function("cipherModSwitchToNext", select_overload<void(const Ciphertext &, Ciphertext &, MemoryPoolHandle)>(&Evaluator::mod_switch_to_next))
        .function("cipherModSwitchTo", select_overload<void(const Ciphertext &, parms_id_type, Ciphertext &, MemoryPoolHandle)>(&Evaluator::mod_switch_to))
        .function("plainModSwitchToNext", select_overload<void(const Plaintext &, Plaintext &)>(&Evaluator::mod_switch_to_next))
        .function("plainModSwitchTo", select_overload<void(const Plaintext &, parms_id_type, Plaintext &)>(&Evaluator::mod_switch_to))
        .function("rescaleToNext", &Evaluator::rescale_to_next)
        .function("rescaleTo", &Evaluator::rescale_to)
        .function("plainTransformToNtt", select_overload<void(const Plaintext &, parms_id_type, Plaintext &, MemoryPoolHandle)>(&Evaluator::transform_to_ntt))
        .function("cipherTransformToNtt", select_overload<void(const Ciphertext &, Ciphertext &)>(&Evaluator::transform_to_ntt))
        .function("cipherTransformFromNtt", select_overload<void(const Ciphertext &, Ciphertext &)>(&Evaluator::transform_from_ntt))
        .function("applyGalois", &Evaluator::apply_galois)
        .function("rotateRows", &Evaluator::rotate_rows)
        .function("rotateColumns", &Evaluator::rotate_columns)
        .function("rotateVector", &Evaluator::rotate_vector)
        .function("complexConjugate", &Evaluator::complex_conjugate);

    class_<KSwitchKeys>("KSwitchKeys")
        .constructor<>()
        .function("saveToString", optional_override([](KSwitchKeys &self,
            compr_mode_type compr_mode) {
            std::ostringstream buffer;
            self.save(buffer, compr_mode);
            std::string contents = buffer.str();
            std::string encoded = b64encode(contents);
            return encoded;
        }))
        .function("loadFromString", optional_override([](KSwitchKeys &self,
            std::shared_ptr<SEALContext>context,
            const std::string &encoded) {
            std::string decoded = b64decode(encoded);
            std::istringstream is(decoded);
            self.load(context, is);
        }));

    class_<RelinKeys, base<KSwitchKeys>> ("RelinKeys")
        .constructor<>();
    class_<GaloisKeys, base<KSwitchKeys>> ("GaloisKeys")
        .constructor<>();

    class_<KeyGenerator>("KeyGenerator")
        .constructor<std::shared_ptr<SEALContext>> ()
        .constructor<std::shared_ptr<SEALContext>, const SecretKey &>()
        .constructor<std::shared_ptr<SEALContext>, const SecretKey &, const PublicKey &>()
        .function("getPublicKey", &KeyGenerator::public_key)
        .function("getSecretKey", &KeyGenerator::secret_key)
        .function("createRelinKeys", select_overload<RelinKeys()>(&KeyGenerator::relin_keys))
        .function("createGaloisKeys", select_overload<GaloisKeys()>(&KeyGenerator::galois_keys));

    class_<PublicKey>("PublicKey")
        .constructor<>()
        .function("saveToString", optional_override([](PublicKey &self,
            compr_mode_type compr_mode) {
            std::ostringstream buffer;
            self.save(buffer, compr_mode);
            std::string contents = buffer.str();
            std::string encoded = b64encode(contents);
            return encoded;
        }))
        .function("loadFromString", optional_override([](PublicKey &self,
            std::shared_ptr<SEALContext>context,
            const std::string &encoded) {
            std::string decoded = b64decode(encoded);
            std::istringstream is(decoded);
            self.load(context, is);
        }));

    class_<SecretKey>("SecretKey")
        .constructor<>()
        .function("saveToString", optional_override([](SecretKey &self,
            compr_mode_type compr_mode) {
            std::ostringstream buffer;
            self.save(buffer, compr_mode);
            std::string contents = buffer.str();
            std::string encoded = b64encode(contents);
            return encoded;
        }))
        .function("loadFromString", optional_override([](SecretKey &self,
            std::shared_ptr<SEALContext>context,
            const std::string &encoded) {
            std::string decoded = b64decode(encoded);
            std::istringstream is(decoded);
            self.load(context, is);
        }));

    class_<Plaintext>("Plaintext")
        .constructor<>()
        .function("saveToString", optional_override([](Plaintext &self,
            compr_mode_type compr_mode) {
            std::ostringstream buffer;
            self.save(buffer, compr_mode);
            std::string contents = buffer.str();
            std::string encoded = b64encode(contents);
            return encoded;
        }))
        .function("loadFromString", optional_override([](Plaintext &self,
            std::shared_ptr<SEALContext>context,
            const std::string &encoded) {
            std::string decoded = b64decode(encoded);
            std::istringstream is(decoded);
            self.load(context, is);
        }))
        .function("shrinkToFit", &Plaintext::shrink_to_fit)
        .function("isZero", &Plaintext::is_zero)
        .function("capacity", optional_override([](Plaintext &self) {
            return self.capacity();
        }))
        .function("coeffCount", optional_override([](Plaintext &self) {
            return self.coeff_count();
        }))
        .function("significantCoeffCount", &Plaintext::significant_coeff_count)
        .function("nonzeroCoeffCount", &Plaintext::nonzero_coeff_count)
        .function("toPolynomial", &Plaintext::to_string)
        .function("isNttForm", select_overload<bool() const>(&Plaintext::is_ntt_form))
        .function("parmsId", select_overload<parms_id_type &()>(&Plaintext::parms_id))
        .function("scale", select_overload<double &()>(&Plaintext::scale))
        .function("pool", optional_override([](Plaintext &self) {
            return self.pool();
        }));

    class_<Ciphertext>("Ciphertext")
        .constructor<>()
        .function("saveToString", optional_override([](Ciphertext &self,
            compr_mode_type compr_mode) {
            std::ostringstream buffer;
            self.save(buffer, compr_mode);
            std::string contents = buffer.str();
            std::string encoded = b64encode(contents);
            return encoded;
        }))
        .function("loadFromString", optional_override([](Ciphertext &self,
            std::shared_ptr<SEALContext>context,
            const std::string &encoded) {
            std::string decoded = b64decode(encoded);
            std::istringstream is(decoded);
            self.load(context, is);
        }))
        .function("coeffModCount", optional_override([](Ciphertext &self) {
            return self.coeff_mod_count();
        }))
        .function("polyModulusDegree", optional_override([](Ciphertext &self) {
            return self.poly_modulus_degree();
        }))
        .function("size", optional_override([](Ciphertext &self) {
            return self.size();
        }))
        .function("sizeCapacity", optional_override([](Ciphertext &self) {
            return self.size_capacity();
        }))
        .function("isTransparent", &Ciphertext::is_transparent)
        .function("isNttForm", select_overload<bool() const>(&Ciphertext::is_ntt_form))
        .function("parmsId", select_overload<parms_id_type &()>(&Ciphertext::parms_id))
        .function("scale", select_overload<double &()>(&Ciphertext::scale))
        .function("pool", optional_override([](Ciphertext &self) {
            return self.pool();
        }));

    class_<IntegerEncoder>("IntegerEncoder")
        .constructor<std::shared_ptr<SEALContext>> ()
        .function("encodeInt32", select_overload<void(std::int32_t, Plaintext &)>(&IntegerEncoder::encode))
        .function("encodeUInt32", select_overload<void(std::uint32_t, Plaintext &)>(&IntegerEncoder::encode))
        .function("decodeInt32", select_overload<std::int32_t(const Plaintext &)>(&IntegerEncoder::decode_int32))
        .function("decodeUInt32", select_overload<std::uint32_t(const Plaintext &)>(&IntegerEncoder::decode_uint32));

    class_<BatchEncoder>("BatchEncoder")
        .constructor<std::shared_ptr<SEALContext>> ()
        .function("encodeVectorInt32", optional_override([](BatchEncoder &self,
            const std::vector<std::int32_t> &values, Plaintext &destination) {
            std::vector<std::int64_t>values_int64;
            convert_vector(values, values_int64);
            return self.BatchEncoder::encode(values_int64, destination);
        }))
        .function("encodeVectorUInt32", optional_override([](BatchEncoder &self,
            const std::vector<std::uint32_t> &values, Plaintext &destination) {
            std::vector<std::uint64_t>values_uint64;
            convert_vector(values, values_uint64);
            return self.BatchEncoder::encode(values_uint64, destination);
        }))
        .function("encode", optional_override([](BatchEncoder &self,
            const val &v, Plaintext &destination,
                const bool &sign) {
            if (sign) {
                std::vector<std::int32_t>temp;
                const auto l = v["length"].as<unsigned>();
                temp.resize(l);
                val memoryView {
                    typed_memory_view(l, temp.data())
                };
                memoryView.call<void>("set", v);

                std::vector<std::int64_t>values;
                convert_vector(temp, values);
                self.BatchEncoder::encode(values, destination);
            } else {
                std::vector<std::uint32_t>temp;
                const auto l = v["length"].as<unsigned>();
                temp.resize(l);
                val memoryView {
                    typed_memory_view(l, temp.data())
                };
                memoryView.call<void>("set", v);

                std::vector<std::uint64_t>values;
                convert_vector(temp, values);
                self.BatchEncoder::encode(values, destination);
            }
        }))
        .function("decodeVectorInt32", optional_override([](BatchEncoder &self,
            const Plaintext &plain, std::vector<std::int32_t> &destination,
                MemoryPoolHandle pool = MemoryManager::GetPool()) {
            std::vector<std::int64_t>destination_int64;
            convert_vector(destination, destination_int64);
            self.BatchEncoder::decode(plain, destination_int64, pool);
            convert_vector(destination_int64, destination);
        }))
        .function("decodeVectorUInt32", optional_override([](BatchEncoder &self,
            const Plaintext &plain, std::vector<std::uint32_t> &destination,
                MemoryPoolHandle pool = MemoryManager::GetPool()) {
            std::vector<std::uint64_t>destination_uint64;
            convert_vector(destination, destination_uint64);
            self.BatchEncoder::decode(plain, destination_uint64, pool);
            convert_vector(destination_uint64, destination);
        }))
        .function("decode", optional_override([](BatchEncoder &self,
            const Plaintext &plain,
                const bool &sign, MemoryPoolHandle pool = MemoryManager::GetPool()) {
            if (sign) {
                std::vector<std::int64_t>destination;
                self.BatchEncoder::decode(plain, destination, pool);

                std::vector<std::int32_t>values;
                convert_vector(destination, values);

                const auto l = values.size();
                return val(typed_memory_view(l, values.data()));
            } else {
                std::vector<std::uint64_t>destination;
                self.BatchEncoder::decode(plain, destination, pool);

                std::vector<std::uint32_t>values;
                convert_vector(destination, values);

                const auto l = values.size();
                return val(typed_memory_view(l, values.data()));
            }
        }))
        .function("slotCount", optional_override([](BatchEncoder &self) {
            return self.slot_count();
        }));

    class_<CKKSEncoder>("CKKSEncoder")
        .constructor<std::shared_ptr<SEALContext>> ()
        .function("encodeVectorDouble", optional_override([](CKKSEncoder &self,
            const std::vector<double> &values,
                double scale, Plaintext &destination,
                MemoryPoolHandle pool = MemoryManager::GetPool()) {
            self.CKKSEncoder::encode(values, scale, destination, pool);
        }))
        .function("decodeVectorDouble", optional_override([](CKKSEncoder &self,
            const Plaintext &plain, std::vector<double> &destination,
                MemoryPoolHandle pool = MemoryManager::GetPool()) {
            self.CKKSEncoder::decode(plain, destination, pool);
        }))
        .function("encode", optional_override([](CKKSEncoder &self,
            const val &v, double scale, Plaintext &destination,
                MemoryPoolHandle pool = MemoryManager::GetPool()) {
            std::vector<double>values;
            const auto l = v["length"].as<unsigned>();
            values.reserve(l);
            values.resize(l);
            val memoryView {
                typed_memory_view(l, values.data())
            };
            memoryView.call<void>("set", v);
            self.CKKSEncoder::encode(values, scale, destination, pool);
        }))
        .function("decode", optional_override([](CKKSEncoder &self,
            const Plaintext &plain, MemoryPoolHandle pool = MemoryManager::GetPool()) {
            std::vector<double>destination;
            self.CKKSEncoder::decode(plain, destination, pool);

            // For some unknown reason, this extra copy is needed or else
            // the result has three (3) zero's at the beginning of the array
            // while the remaining slots are correct. Even when we print
            // the original vector's values (which are correct)...
            std::vector<double>values;
            convert_vector(destination, values);

            const auto l = values.size();
            return val(typed_memory_view(l, values.data()));
        }))
        .function("slotCount", optional_override([](CKKSEncoder &self) {
            return self.slot_count();
        }));

    class_<MemoryPoolHandle>("MemoryPoolHandle")
        .constructor<>()
        .class_function("MemoryPoolHandleGlobal", &MemoryPoolHandle::Global)
        .class_function("MemoryPoolHandleThreadLocal", &MemoryPoolHandle::ThreadLocal)
        .class_function("MemoryPoolHandleNew", &MemoryPoolHandle::New);

    class_<MemoryManager>("MemoryManager")
        .function("GetPool", select_overload<MemoryPoolHandle(mm_prof_opt_t)>(&MemoryManager::GetPool));

    class_<MMProf>("MMProf");

    class_<MMProfGlobal, base<MMProf>> ("MMProfGlobal")
        .function("getPool", &MMProfGlobal::get_pool);

    class_<MMProfNew, base<MMProf>> ("MMProfNew")
        .function("getPool", &MMProfNew::get_pool);

    class_<MMProfFixed, base<MMProf>> ("MMProfFixed")
        .function("getPool", &MMProfFixed::get_pool);

    class_<MMProfThreadLocal, base<MMProf>> ("MMProfThreadLocal")
        .function("getPool", &MMProfThreadLocal::get_pool);

    class_<Encryptor>("Encryptor")
        .constructor<std::shared_ptr<SEALContext>, const PublicKey &>()
        // embind caveat, have to use this overload as the constructor for symmetric encryption
        .constructor<std::shared_ptr<SEALContext>, const PublicKey &, const SecretKey &>()
        .function("setPublicKey", &Encryptor::set_public_key)
        .function("setSecretKey", &Encryptor::set_secret_key)
        .function("encrypt", &Encryptor::encrypt)
        .function("encryptSymmetric", &Encryptor::encrypt_symmetric);

    class_<Decryptor>("Decryptor")
        .constructor<std::shared_ptr<SEALContext>, const SecretKey &>()
        .function("decrypt", &Decryptor::decrypt)
        .function("invariantNoiseBudget", &Decryptor::invariant_noise_budget);

    enum_<scheme_type>("SchemeType")
        .value("none", scheme_type::none)
        .value("BFV", scheme_type::BFV)
        .value("CKKS", scheme_type::CKKS);

    //enum_<mm_prof_opt>("mm_prof_opt")
    //    .value("DEFAULT", mm_prof_opt::DEFAULT)
    //    .value("FORCE_GLOBAL", mm_prof_opt::FORCE_GLOBAL)
    //    .value("FORCE_NEW", mm_prof_opt::FORCE_NEW)
    //    .value("FORCE_THREAD_LOCAL", mm_prof_opt::FORCE_THREAD_LOCAL)
    //    ;
}

#endif
