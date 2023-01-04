#include <cstdint>
#include <emscripten/bind.h>
#include <iomanip>
#include <stdexcept>
#include <typeinfo>
#include "base64.h"
#include "seal.h"

using namespace std;
using namespace emscripten;
using namespace seal;

/*
  Helper to convert a string to a number type.
*/
template <typename T>
void string_to_number(std::string &str, T &numb)
{
    std::istringstream is(str);
    is >> numb;
}

/*
  Transform a JS TypedArray into a Vector of the appropriate type (zero copy)
*/
template <typename T>
std::vector<T> vecFromJSArrayFast(const val &v)
{
    std::vector<T> rv;
    const size_t l = v["length"].as<std::size_t>();
    rv.resize(l);
    val memoryView{ typed_memory_view(l, rv.data()) };
    memoryView.call<void>("set", v);
    return rv;
};

/*
  Transform a JS Array of strings into a Vector of the appropriate type (slow)
*/
template <typename T>
std::vector<T> vecFromJSArrayString(const val &v)
{
    const std::size_t length = v["length"].as<std::size_t>();
    std::vector<T> values;
    values.reserve(length);
    // Right now, embind doesn't support BigInt from JS => WASM
    // The work arround is to perform string conversion.
    for (std::size_t i = 0; i < length; ++i)
    {
        std::string string_value = v[i].as<std::string>();
        T num_value;
        string_to_number(string_value, num_value);
        values.push_back(num_value);
    }
    return values;
};

/*
  Transform a JS Array of strings into a Vector of Modulus (slow)
*/
std::vector<Modulus> vecFromJSArrayStringModulus(const val &v)
{
    const std::size_t length = v["length"].as<std::size_t>();
    std::vector<Modulus> values;
    values.reserve(length);
    // Right now, embind doesn't support BigInt from JS => WASM
    // The work arround is to perform string conversion.
    for (std::size_t i = 0; i < length; ++i)
    {
        std::string string_value = v[i].as<std::string>();
        uint64_t num_value;
        string_to_number(string_value, num_value);
        values.push_back(num_value);
    }
    return values;
};

/*
  Converts a Vector to a JS TypedArray (zero copy)
*/
template <typename T>
emscripten::val jsArrayFromVec(const std::vector<T> &vec)
{
    const size_t l = vec.size();
    return val(typed_memory_view(l, vec.data()));
};

/*
  Converts a Vector to a JS Array of strings (slow)
*/
template <typename T>
emscripten::val jsArrayStringFromVec(const std::vector<T> &vec)
{
    const size_t length = vec.size();

    std::vector<std::string> result_strings;
    result_strings.reserve(length);
    const std::type_info &ti = typeid(T);

    for (auto number : vec)
    {
        result_strings.push_back(std::to_string(number));
    }

    emscripten::val result = emscripten::val::array(result_strings.begin(), result_strings.end());
    return result;
};
/*
  Converts a Vector holding Modulus to a JS Array of strings (slow)
*/
emscripten::val jsArrayStringFromVecModulus(const std::vector<Modulus> &vec)
{
    const size_t length = vec.size();

    std::vector<std::string> result_strings;
    result_strings.reserve(length);

    for (auto number : vec)
    {
        result_strings.push_back(std::to_string(number.value()));
    }

    emscripten::val result = emscripten::val::array(result_strings.begin(), result_strings.end());
    return result;
};
/*
  Copies a Vector of type T1 to type T2
*/
template <typename T1, typename T2>
void copy_vector(const std::vector<T1> &vector_input, std::vector<T2> &vector_output)
{
    vector_output.assign(vector_input.begin(), vector_input.end());
};

/*
Helper function: Prints the parameters in a SEALContext.
*/
std::string printContext(const SEALContext &context)
{
    auto context_data = context.key_context_data();

    /*
    Which scheme are we using?
    */
    std::string scheme_name;
    switch (context_data->parms().scheme())
    {
    case seal::scheme_type::bfv:
        scheme_name = "bfv";
        break;
    case seal::scheme_type::ckks:
        scheme_name = "ckks";
        break;
    case seal::scheme_type::bgv:
        scheme_name = "bgv";
        break;
    default:
        throw std::invalid_argument("unsupported scheme");
    }

    std::ostringstream oss;

    oss << "/" << std::endl;
    oss << "| Encryption parameters :" << std::endl;
    oss << "|   scheme: " << scheme_name << std::endl;
    oss << "|   poly_modulus_degree: " << context_data->parms().poly_modulus_degree() << std::endl;

    /*
    Print the size of the true (product) coefficient modulus.
    */
    oss << "|   coeff_modulus size: ";
    oss << context_data->total_coeff_modulus_bit_count() << " (";
    auto coeff_modulus = context_data->parms().coeff_modulus();
    std::size_t coeff_modulus_size = coeff_modulus.size();
    for (std::size_t i = 0; i < coeff_modulus_size - 1; i++)
    {
        oss << coeff_modulus[i].bit_count() << " + ";
    }
    oss << coeff_modulus.back().bit_count();
    oss << ") bits" << std::endl;

    /*
    For the 'bfv'' scheme print the plain_modulus parameter.
    */
    if (context_data->parms().scheme() == seal::scheme_type::bfv ||
        context_data->parms().scheme() == seal::scheme_type::bgv)
    {
        oss << "|   plain_modulus: " << context_data->parms().plain_modulus().value() << std::endl;
    }

    oss << "\\" << std::endl;
    return oss.str();
}

/*
 Gets the exception string from the thrown pointer
*/
std::string get_exception(intptr_t ptr)
{
    auto exception = reinterpret_cast<std::exception *>(ptr);
    std::string error_string = exception->what();
    return error_string;
}

template <class F>
struct y_combinator
{
    F f; // the lambda will be stored here

    // a forwarding operator():
    template <class... Args>
    decltype(auto) operator()(Args &&...args) const
    {
        // we pass ourselves to f, then the arguments.
        // the lambda should take the first argument as `auto&& recurse` or similar.
        return f(*this, std::forward<Args>(args)...);
    }
};
// helper function that deduces the type of the lambda:
template <class F>
y_combinator<std::decay_t<F>> make_y_combinator(F &&f)
{
    return { std::forward<F>(f) };
}

/*
 * Dummy main so the linker will not perform DCE
 */
int main()
{
    return 0;
}

EMSCRIPTEN_BINDINGS(SEAL)
{
    emscripten::function("getException", &get_exception);
    emscripten::function("jsArrayUint8FromVec", select_overload<val(const std::vector<uint8_t> &)>(&jsArrayFromVec));
    emscripten::function("jsArrayInt32FromVec", select_overload<val(const std::vector<int32_t> &)>(&jsArrayFromVec));
    emscripten::function("jsArrayUint32FromVec", select_overload<val(const std::vector<uint32_t> &)>(&jsArrayFromVec));
    emscripten::function("jsArrayFloat64FromVec", select_overload<val(const std::vector<double> &)>(&jsArrayFromVec));
    emscripten::function(
        "jsArrayStringFromVecInt64", select_overload<val(const std::vector<int64_t> &)>(&jsArrayStringFromVec));
    emscripten::function(
        "jsArrayStringFromVecUint64", select_overload<val(const std::vector<uint64_t> &)>(&jsArrayStringFromVec));
    emscripten::function(
        "jsArrayStringFromVecModulus",
        select_overload<val(const std::vector<Modulus> &)>(&jsArrayStringFromVecModulus));
    emscripten::function("vecFromArrayUint8", select_overload<std::vector<uint8_t>(const val &)>(&vecFromJSArrayFast));
    emscripten::function("vecFromArrayInt32", select_overload<std::vector<int32_t>(const val &)>(&vecFromJSArrayFast));
    emscripten::function(
        "vecFromArrayUint32", select_overload<std::vector<uint32_t>(const val &)>(&vecFromJSArrayFast));
    emscripten::function("vecFromArrayFloat64", select_overload<std::vector<double>(const val &)>(&vecFromJSArrayFast));
    emscripten::function(
        "vecFromArrayBigInt64", select_overload<std::vector<int64_t>(const val &)>(&vecFromJSArrayString));
    emscripten::function(
        "vecFromArrayBigUint64", select_overload<std::vector<uint64_t>(const val &)>(&vecFromJSArrayString));
    emscripten::function(
        "vecFromArrayModulus", select_overload<std::vector<Modulus>(const val &)>(&vecFromJSArrayStringModulus));

    register_vector<Plaintext>("std::vector<Plaintext>");
    register_vector<Ciphertext>("std::vector<Ciphertext>");
    register_vector<uint8_t>("std::vector<uint8_t>");
    register_vector<int32_t>("std::vector<int32_t>");
    register_vector<uint32_t>("std::vector<uint32_t>");
    register_vector<int64_t>("std::vector<int64_t>");
    register_vector<uint64_t>("std::vector<uint64_t>");
    register_vector<double>("std::vector<double>");
    register_vector<std::complex<double>>("std::vector<std::complex<double>>");
    register_vector<Modulus>("std::vector<Modulus>");

    class_<util::HashFunction>("util::HashFunction")
        .class_property("hashBlockUint64Count", &util::HashFunction::hash_block_uint64_count)
        .class_property("hashBlockByteCount", &util::HashFunction::hash_block_byte_count)
        .class_function("hash", &util::HashFunction::hash, allow_raw_pointers());

    // using parms_id_type = util::HashFunction::hash_block_type
    // using hash_block_type std::array<std::uint64_t, hash_block_uint64_count>;

    class_<parms_id_type>("ParmsIdType")
        .constructor<>()
        .constructor<parms_id_type &&>() // Move via constructor overload
        .function("values", optional_override([](parms_id_type &self) {
                      std::vector<std::string> result_strings;
                      result_strings.reserve(self.size());

                      for (auto number : self)
                      {
                          result_strings.push_back(std::to_string(number));
                      }

                      emscripten::val result = emscripten::val::array(result_strings.begin(), result_strings.end());
                      return result;
                  }));

    enum_<sec_level_type>("SecLevelType")
        .value("none", sec_level_type::none)
        .value("tc128", sec_level_type::tc128)
        .value("tc192", sec_level_type::tc192)
        .value("tc256", sec_level_type::tc256);

    enum_<compr_mode_type>("ComprModeType")
        .value("none", compr_mode_type::none)
#ifdef SEAL_USE_ZLIB
        .value("zlib", compr_mode_type::zlib)
#endif
#ifdef SEAL_USE_ZSTD
        .value("zstd", compr_mode_type::zstd)
#endif
        ;

    class_<CoeffModulus>("CoeffModulus")
        .class_function("MaxBitCount", &CoeffModulus::MaxBitCount)
        .class_function("BFVDefault", &CoeffModulus::BFVDefault)
        .class_function("CreateFromArray", optional_override([](const std::size_t &poly_modulus_degree, const val &v) {
                            std::vector<int> bit_sizes;
                            const std::size_t l = v["length"].as<std::size_t>();
                            bit_sizes.resize(l);
                            val memoryView{ typed_memory_view(l, bit_sizes.data()) };
                            memoryView.call<void>("set", v);
                            std::vector<Modulus> coeffModulus = CoeffModulus::Create(poly_modulus_degree, bit_sizes);
                            return coeffModulus;
                        }));
    class_<PlainModulus>("PlainModulus")
        .class_function("Batching", select_overload<Modulus(std::size_t, int)>(&PlainModulus::Batching))
        .class_function(
            "BatchingVector",
            select_overload<std::vector<Modulus>(std::size_t, std::vector<int>)>(&PlainModulus::Batching));

    class_<Modulus>("Modulus")
        .constructor<>()
        .constructor<Modulus &&>() // Move via constructor overload
        .function("isZero", optional_override([](Modulus &self) { return self.is_zero(); }))
        .function("isPrime", optional_override([](Modulus &self) { return self.is_prime(); }))
        .function("bitCount", optional_override([](Modulus &self) { return self.bit_count(); }))
        .function("saveToString", optional_override([](Modulus &self, compr_mode_type compr_mode) {
                      std::ostringstream buffer;
                      self.save(buffer, compr_mode);
                      std::string contents = buffer.str();
                      std::string encoded = b64encode(contents);
                      return encoded;
                  }))
        .function("saveToArray", optional_override([](Modulus &self, compr_mode_type compr_mode) {
                      std::ostringstream buffer;
                      self.save(buffer, compr_mode);
                      std::string const contents{ buffer.str() };
                      std::vector<std::uint8_t> const strVector{ contents.begin(), contents.end() };
                      return strVector;
                  }))
        .function("loadFromString", optional_override([](Modulus &self, const std::string &encoded) {
                      std::string decoded = b64decode(encoded);
                      std::istringstream is(decoded);
                      self.load(is);
                  }))
        .function("loadFromArray", optional_override([](Modulus &self, const val &v) {
                      // Get the size of the TypedArray input
                      const size_t length = v["length"].as<unsigned>();
                      // Create a temporary vector to store the TypedArray values
                      std::vector<std::uint8_t> temp;
                      // Resize to the number of elements in the TypedArray
                      temp.resize(length);
                      // Construct a memory view on the temp vector
                      const val memoryView{ typed_memory_view(length, temp.data()) };
                      // Set the data in the vector from the JS side.
                      memoryView.call<void>("set", v);
                      // Convert the vector into a stringstream
                      std::stringstream ss;
                      // Copy the vector to the stringstream
                      std::copy(temp.begin(), temp.end(), std::ostream_iterator<std::uint8_t>(ss));
                      // Load from the stringstream
                      self.load(ss);
                  }))
        .function("setValue", optional_override([](Modulus &self, const std::string &v) {
                      std::uint64_t value;
                      std::istringstream is(v);
                      is >> value;
                      self = std::move(value);
                  }))
        .function("value", optional_override([](Modulus &self) {
                      uint64_t value = self.value();
                      std::ostringstream oss;
                      oss << value;
                      std::string intAsString = oss.str();
                      return intAsString;
                  }));

    class_<EncryptionParameters>("EncryptionParameters")
        .constructor<scheme_type>()
        .function("setPolyModulusDegree", &EncryptionParameters::set_poly_modulus_degree)
        .function("setCoeffModulus", &EncryptionParameters::set_coeff_modulus)
        .function("setPlainModulus", select_overload<void(const Modulus &)>(&EncryptionParameters::set_plain_modulus))
        .function("scheme", optional_override([](EncryptionParameters &self) { return self.scheme(); }))
        .function("polyModulusDegree", optional_override([](EncryptionParameters &self) {
                      return self.poly_modulus_degree();
                  }))
        .function("coeffModulus", optional_override([](EncryptionParameters &self) { return self.coeff_modulus(); }))
        .function("plainModulus", optional_override([](EncryptionParameters &self) { return self.plain_modulus(); }))
        .function("parmsId", optional_override([](EncryptionParameters &self) { return self.parms_id(); }))
        .function("saveToString", optional_override([](EncryptionParameters &self, compr_mode_type compr_mode) {
                      std::ostringstream buffer;
                      self.save(buffer, compr_mode);
                      std::string contents = buffer.str();
                      std::string encoded = b64encode(contents);
                      return encoded;
                  }))
        .function("saveToArray", optional_override([](EncryptionParameters &self, compr_mode_type compr_mode) {
                      std::ostringstream buffer;
                      self.save(buffer, compr_mode);
                      std::string const contents{ buffer.str() };
                      std::vector<std::uint8_t> const strVector{ contents.begin(), contents.end() };
                      return strVector;
                  }))
        .function("loadFromString", optional_override([](EncryptionParameters &self, const std::string &encoded) {
                      std::string decoded = b64decode(encoded);
                      std::istringstream is(decoded);
                      self.load(is);
                  }))
        .function("loadFromArray", optional_override([](EncryptionParameters &self, const val &v) {
                      // Get the size of the TypedArray input
                      const size_t length = v["length"].as<unsigned>();
                      // Create a temporary vector to store the TypedArray values
                      std::vector<std::uint8_t> temp;
                      // Resize to the number of elements in the TypedArray
                      temp.resize(length);
                      // Construct a memory view on the temp vector
                      const val memoryView{ typed_memory_view(length, temp.data()) };
                      // Set the data in the vector from the JS side.
                      memoryView.call<void>("set", v);
                      // Convert the vector into a stringstream
                      std::stringstream ss;
                      // Copy the vector to the stringstream
                      std::copy(temp.begin(), temp.end(), std::ostream_iterator<std::uint8_t>(ss));
                      // Load from the stringstream
                      self.load(ss);
                  }));

    class_<EncryptionParameterQualifiers>("EncryptionParameterQualifiers")
        .function("parametersSet", optional_override([](EncryptionParameterQualifiers &self) {
                      return self.parameters_set();
                  }))
        .property("usingFFT", &EncryptionParameterQualifiers::using_fft)
        .property("usingNTT", &EncryptionParameterQualifiers::using_ntt)
        .property("usingBatching", &EncryptionParameterQualifiers::using_batching)
        .property("usingFastPlainLift", &EncryptionParameterQualifiers::using_fast_plain_lift)
        .property("usingDescendingModulusChain", &EncryptionParameterQualifiers::using_descending_modulus_chain)
        .property("securityLevel", &EncryptionParameterQualifiers::sec_level);

    class_<std::shared_ptr<const SEALContext::ContextData>>("ContextData")
        .function("parms", optional_override([](std::shared_ptr<const SEALContext::ContextData> &self) {
                      return self->parms(); // Returns a pointer to EncryptionParameters
                  }))
        .function("parmsId", optional_override([](std::shared_ptr<const SEALContext::ContextData> &self) {
                      return self->parms_id(); // Returns a pointer to ParmsIdType
                  }))
        .function("qualifiers", optional_override([](std::shared_ptr<const SEALContext::ContextData> &self) {
                      return self->qualifiers(); // Returns a pointer to EncryptionParameterQualifiers
                  }))
        //        .function("totalCoeffModulus", optional_override([](std::shared_ptr<const SEALContext::ContextData>
        //        &self) {
        //               return self->total_coeff_modulus();
        //          }), allow_raw_pointers())
        .function(
            "totalCoeffModulusBitCount", optional_override([](std::shared_ptr<const SEALContext::ContextData> &self) {
                return self->total_coeff_modulus_bit_count();
            }))
        //        .function("coeffDivPlainModulus", optional_override([](std::shared_ptr<const SEALContext::ContextData>
        //        &self) {
        //               return self->coeff_div_plain_modulus();
        //          }), allow_raw_pointers())
        //        .function("baseConverter", &SEALContext::ContextData::base_converter)
        //        .function("smallNttTables", &SEALContext::ContextData::small_ntt_tables)
        //        .function("plainNttTables", &SEALContext::ContextData::plain_ntt_tables)
        //        .function("plainUpperHalfThreshold", optional_override([](std::shared_ptr<const
        //        SEALContext::ContextData> &self) {
        //               return self->plain_upper_half_threshold();
        //          }), allow_raw_pointers())
        //        .function("plainUpperHalfIncrement", optional_override([](std::shared_ptr<const
        //        SEALContext::ContextData> &self) {
        //               return self->plain_upper_half_increment();
        //          }), allow_raw_pointers())
        //        .function("upperHalfThreshold", optional_override([](std::shared_ptr<const SEALContext::ContextData>
        //        &self) {
        //               return self->upper_half_threshold();
        //          }), allow_raw_pointers())
        //        .function("upperHalfIncrement", optional_override([](std::shared_ptr<const SEALContext::ContextData>
        //        &self) {
        //               return self->upper_half_increment();
        //          }), allow_raw_pointers())
        //        .function("coeffModPlainModulus", optional_override([](std::shared_ptr<const SEALContext::ContextData>
        //        &self) {
        //               return self->coeff_mod_plain_modulus();
        //          }))
        .function("prevContextData", optional_override([](std::shared_ptr<const SEALContext::ContextData> &self) {
                      return self->prev_context_data(); // Returns a pointer to ContextData
                  }))
        .function("nextContextData", optional_override([](std::shared_ptr<const SEALContext::ContextData> &self) {
                      return self->next_context_data(); // Returns a pointer to ContextData
                  }))
        .function("chainIndex", optional_override([](std::shared_ptr<const SEALContext::ContextData> &self) {
                      return self->chain_index();
                  }));

    class_<SEALContext>("SEALContext")
        .constructor<const EncryptionParameters &, bool, sec_level_type>()
        .function("copy", optional_override([](SEALContext &self, const SEALContext &copy) {
                      self = copy; // Copy via assignment overload
                  }))
        .function("clone", optional_override([](const SEALContext &self) {
                      SEALContext clone = self; // Copy via assignment overload
                      return clone;
                  }))
        .function("move", optional_override([](SEALContext &self, SEALContext &&assign) {
                      // If the original assign was const, this will default to a copy assignment
                      self = std::move(assign);
                  }))
        .function("toHuman", &printContext)
        .function("getContextData", &SEALContext::get_context_data)
        .function("keyContextData", &SEALContext::key_context_data)
        .function("firstContextData", &SEALContext::first_context_data)
        .function("lastContextData", &SEALContext::last_context_data)
        .function("parametersSet", &SEALContext::parameters_set)
        .function("keyParmsId", optional_override([](SEALContext &self) { return self.key_parms_id(); }))
        .function("firstParmsId", optional_override([](SEALContext &self) { return self.first_parms_id(); }))
        .function("lastParmsId", optional_override([](SEALContext &self) { return self.last_parms_id(); }))
        .function("usingKeyswitching", optional_override([](SEALContext &self) { return self.using_keyswitching(); }));

    class_<Evaluator>("Evaluator")
        .constructor<const SEALContext &>()
        .function("negate", &Evaluator::negate)
        .function("add", &Evaluator::add)
        .function("addPlain", &Evaluator::add_plain)
        .function("sub", &Evaluator::sub)
        .function("subPlain", &Evaluator::sub_plain)
        .function("multiply", &Evaluator::multiply)
        .function("multiplyPlain", &Evaluator::multiply_plain)
        .function("square", &Evaluator::square)
        .function(
            "exponentiate", optional_override([](Evaluator &self, const Ciphertext &encrypted, std::uint32_t exponent,
                                                 const RelinKeys &relin_keys, Ciphertext &destination,
                                                 MemoryPoolHandle pool = MemoryManager::GetPool()) {
                std::uint64_t exponent_uint64 = (uint64_t)exponent;
                return self.Evaluator::exponentiate(encrypted, exponent_uint64, relin_keys, destination, pool);
            }))
        .function("relinearize", &Evaluator::relinearize)
        .function(
            "cipherModSwitchToNext", select_overload<void(const Ciphertext &, Ciphertext &, MemoryPoolHandle) const>(
                                         &Evaluator::mod_switch_to_next))
        .function(
            "cipherModSwitchTo",
            select_overload<void(const Ciphertext &, parms_id_type, Ciphertext &, MemoryPoolHandle) const>(
                &Evaluator::mod_switch_to))
        .function(
            "plainModSwitchToNext",
            select_overload<void(const Plaintext &, Plaintext &) const>(&Evaluator::mod_switch_to_next))
        .function(
            "plainModSwitchTo",
            select_overload<void(const Plaintext &, parms_id_type, Plaintext &) const>(&Evaluator::mod_switch_to))
        .function("rescaleToNext", &Evaluator::rescale_to_next)
        .function("rescaleTo", &Evaluator::rescale_to)
        .function("modReduceToNext", &Evaluator::mod_reduce_to_next)
        .function("modReduceTo", &Evaluator::mod_reduce_to)
        .function(
            "plainTransformToNtt",
            select_overload<void(const Plaintext &, parms_id_type, Plaintext &, MemoryPoolHandle) const>(
                &Evaluator::transform_to_ntt))
        .function(
            "cipherTransformToNtt",
            select_overload<void(const Ciphertext &, Ciphertext &) const>(&Evaluator::transform_to_ntt))
        .function(
            "cipherTransformFromNtt",
            select_overload<void(const Ciphertext &, Ciphertext &) const>(&Evaluator::transform_from_ntt))
        .function(
            "applyGalois", optional_override([](Evaluator &self, const Ciphertext &encrypted, const std::uint32_t g_elt,
                                                const GaloisKeys &gal_keys, Ciphertext &destination,
                                                MemoryPoolHandle pool = MemoryManager::GetPool()) {
                std::uint64_t galois_elt = (uint64_t)g_elt;
                self.apply_galois(encrypted, g_elt, gal_keys, destination, pool);
            }))
        .function("rotateRows", &Evaluator::rotate_rows)
        .function("rotateColumns", &Evaluator::rotate_columns)
        .function("rotateVector", &Evaluator::rotate_vector)
        .function("complexConjugate", &Evaluator::complex_conjugate)
        .function(
            "sumElements", optional_override([](Evaluator &self, const Ciphertext &encrypted,
                                                const GaloisKeys &gal_keys, scheme_type scheme, Ciphertext &destination,
                                                MemoryPoolHandle pool = MemoryManager::GetPool()) {
                if (scheme == scheme_type::none)
                {
                    throw std::logic_error("unsupported scheme");
                }
                // Check if power of 2 via complement and compare method
                if (!((encrypted.poly_modulus_degree() != 0) &&
                      ((encrypted.poly_modulus_degree() & (encrypted.poly_modulus_degree() - 1)) == 0)))
                {
                    throw std::out_of_range("encrypted poly_modulus_degree must be a power of 2");
                }

                // create a copy to mutate
                Ciphertext temp = encrypted;
                int rotateSteps = temp.poly_modulus_degree() / 4;

                if (scheme == scheme_type::ckks)
                {
                    // define recursive lambda
                    auto sum_elements = make_y_combinator([](auto &&sum_elements, Evaluator &self, Ciphertext &a,
                                                             int steps, const GaloisKeys &gal_keys,
                                                             Ciphertext &destination, MemoryPoolHandle pool) {
                        if (steps < 1)
                        {
                            destination = std::move(a);
                            return;
                        }
                        self.rotate_vector(a, steps, gal_keys, destination, pool);
                        self.add(a, destination, a);
                        return sum_elements(self, a, steps / 2, gal_keys, destination, pool);
                    });

                    // recursively sum
                    sum_elements(self, temp, rotateSteps, gal_keys, destination, pool);
                    return;
                }

                if (scheme == scheme_type::bfv || scheme == scheme_type::bgv)
                {
                    // define recursive lambda
                    auto sum_elements = make_y_combinator([](auto &&sum_elements, Evaluator &self, Ciphertext &a,
                                                             int steps, const GaloisKeys &gal_keys,
                                                             Ciphertext &destination, MemoryPoolHandle pool) {
                        if (steps < 1)
                        {
                            destination = std::move(a);
                            return;
                        }
                        self.rotate_rows(a, steps, gal_keys, destination, pool);
                        self.rotate_columns(destination, gal_keys, destination, pool);
                        self.add(a, destination, a);
                        return sum_elements(self, a, steps / 2, gal_keys, destination, pool);
                    });
                    // Perform first step to optimize loop
                    self.rotate_columns(temp, gal_keys, destination, pool);
                    self.add(temp, destination, temp);

                    // recursively sum
                    sum_elements(self, temp, rotateSteps, gal_keys, destination, pool);
                }
            }))
        .function(
            "linearTransformPlain",
            optional_override([](Evaluator &self, const Ciphertext &ct, const std::vector<Plaintext> &U_diagonals,
                                 const GaloisKeys &gal_keys) {
                // Get the size of the vector of diagonals
                const std::size_t diagSize = U_diagonals.size();
                // Fill ct with duplicate
                Ciphertext ct_rot;

                // Rotate the input cipher to the left
                self.Evaluator::rotate_vector(ct, -diagSize, gal_keys, ct_rot);

                // Create a new cipher
                Ciphertext ct_new;

                // Add the rotated value to the original and store it in the new cipher
                self.Evaluator::add(ct, ct_rot, ct_new);

                // Create a new result cipher of the same size as the vector of diagonals
                vector<Ciphertext> ct_result(diagSize);

                // Multiply each new cipher by each of the plaintext diagonals and store it in the result cipher vector
                self.Evaluator::multiply_plain(ct_new, U_diagonals[0], ct_result[0]);

                // Rotate and multiply each new cipher
                for (int l = 1; l < diagSize; l++)
                {
                    Ciphertext temp_rot;
                    self.Evaluator::rotate_vector(ct_new, l, gal_keys, temp_rot);
                    if (U_diagonals[l].is_zero())
                    {
                        continue;
                    }
                    self.Evaluator::multiply_plain(temp_rot, U_diagonals[l], ct_result[l]);
                }
                Ciphertext ct_prime;
                self.Evaluator::add_many(ct_result, ct_prime);

                return ct_prime;
            }));

    class_<KSwitchKeys>("KSwitchKeys")
        .constructor<>()
        .function("size", optional_override([](KSwitchKeys &self) { return self.size(); }))
        .function("saveToString", optional_override([](KSwitchKeys &self, compr_mode_type compr_mode) {
                      std::ostringstream buffer;
                      self.save(buffer, compr_mode);
                      std::string contents = buffer.str();
                      std::string encoded = b64encode(contents);
                      return encoded;
                  }))
        .function("saveToArray", optional_override([](KSwitchKeys &self, compr_mode_type compr_mode) {
                      std::ostringstream buffer;
                      self.save(buffer, compr_mode);
                      std::string const contents{ buffer.str() };
                      std::vector<std::uint8_t> const strVector{ contents.begin(), contents.end() };
                      return strVector;
                  }))
        .function(
            "loadFromString",
            optional_override([](KSwitchKeys &self, SEALContext &context, const std::string &encoded) {
                std::string decoded = b64decode(encoded);
                std::istringstream is(decoded);
                self.load(context, is);
            }))
        .function("loadFromArray", optional_override([](KSwitchKeys &self, SEALContext &context, const val &v) {
                      // Get the size of the TypedArray input
                      const size_t length = v["length"].as<unsigned>();
                      // Create a temporary vector to store the TypedArray values
                      std::vector<std::uint8_t> temp;
                      // Resize to the number of elements in the TypedArray
                      temp.resize(length);
                      // Construct a memory view on the temp vector
                      const val memoryView{ typed_memory_view(length, temp.data()) };
                      // Set the data in the vector from the JS side.
                      memoryView.call<void>("set", v);
                      // Convert the vector into a stringstream
                      std::stringstream ss;
                      // Copy the vector to the stringstream
                      std::copy(temp.begin(), temp.end(), std::ostream_iterator<std::uint8_t>(ss));
                      // Load from the stringstream
                      self.load(context, ss);
                  }));

    class_<RelinKeys, base<KSwitchKeys>>("RelinKeys")
        .constructor<>()
        .constructor<RelinKeys &&>() // Move via constructor overload
        .function("getIndex", optional_override([](RelinKeys &self, const std::uint32_t &key_power) {
                      return self.get_index(key_power);
                  }))
        .function("hasKey", optional_override([](RelinKeys &self, const std::uint32_t &key_power) {
                      return self.has_key(key_power);
                  }))
        //        .function("key", optional_override([](RelinKeys &self, const std::uint32_t &key_power) {
        //                return self.key(key_power);
        //            }))
        .function("copy", optional_override([](RelinKeys &self, const RelinKeys &copy) {
                      self = copy; // Copy via assignment overload
                  }))
        .function("clone", optional_override([](const RelinKeys &self) {
                      RelinKeys clone = self; // Copy via assignment overload
                      return clone;
                  }))
        .function("move", optional_override([](RelinKeys &self, RelinKeys &&assign) {
                      // If the original assign was const, this will default to a copy assignment
                      self = std::move(assign);
                  }));

    class_<GaloisKeys, base<KSwitchKeys>>("GaloisKeys")
        .constructor<>()
        .constructor<GaloisKeys &&>() // Move via constructor overload
        .function("getIndex", optional_override([](GaloisKeys &self, const std::uint32_t &g_elt) {
                      return self.get_index(g_elt);
                  }))
        .function("hasKey", optional_override([](GaloisKeys &self, const std::uint32_t &g_elt) {
                      return self.has_key(g_elt);
                  }))
        //        .function("key", optional_override([](GaloisKeys &self, const std::uint32_t &g_elt) {
        //                std::uint64_t galois_elt = (uint64_t) g_elt;
        //                return self.key(galois_elt);
        //            }))
        .function("copy", optional_override([](GaloisKeys &self, const GaloisKeys &copy) {
                      self = copy; // Copy via assignment overload
                  }))
        .function("clone", optional_override([](const GaloisKeys &self) {
                      GaloisKeys clone = self; // Copy via assignment overload
                      return clone;
                  }))
        .function("move", optional_override([](GaloisKeys &self, GaloisKeys &&assign) {
                      // If the original assign was const, this will default to a copy assignment
                      self = std::move(assign);
                  }));
    class_<Serializable<PublicKey>>("Serializable<PublicKey>")
        .function("saveToString", optional_override([](Serializable<PublicKey> &self, compr_mode_type compr_mode) {
                      std::ostringstream buffer;
                      self.save(buffer, compr_mode);
                      std::string contents = buffer.str();
                      std::string encoded = b64encode(contents);
                      return encoded;
                  }))
        .function("saveToArray", optional_override([](Serializable<PublicKey> &self, compr_mode_type compr_mode) {
                      std::ostringstream buffer;
                      self.save(buffer, compr_mode);
                      std::string const contents{ buffer.str() };
                      std::vector<std::uint8_t> const strVector{ contents.begin(), contents.end() };
                      return strVector;
                  }));
    class_<Serializable<RelinKeys>>("Serializable<RelinKeys>")
        .function("saveToString", optional_override([](Serializable<RelinKeys> &self, compr_mode_type compr_mode) {
                      std::ostringstream buffer;
                      self.save(buffer, compr_mode);
                      std::string contents = buffer.str();
                      std::string encoded = b64encode(contents);
                      return encoded;
                  }))
        .function("saveToArray", optional_override([](Serializable<RelinKeys> &self, compr_mode_type compr_mode) {
                      std::ostringstream buffer;
                      self.save(buffer, compr_mode);
                      std::string const contents{ buffer.str() };
                      std::vector<std::uint8_t> const strVector{ contents.begin(), contents.end() };
                      return strVector;
                  }));
    class_<Serializable<GaloisKeys>>("Serializable<GaloisKeys>")
        .function("saveToString", optional_override([](Serializable<GaloisKeys> &self, compr_mode_type compr_mode) {
                      std::ostringstream buffer;
                      self.save(buffer, compr_mode);
                      std::string contents = buffer.str();
                      std::string encoded = b64encode(contents);
                      return encoded;
                  }))
        .function("saveToArray", optional_override([](Serializable<GaloisKeys> &self, compr_mode_type compr_mode) {
                      std::ostringstream buffer;
                      self.save(buffer, compr_mode);
                      std::string const contents{ buffer.str() };
                      std::vector<std::uint8_t> const strVector{ contents.begin(), contents.end() };
                      return strVector;
                  }));
    class_<Serializable<Ciphertext>>("Serializable<Ciphertext>")
        .function("saveToString", optional_override([](Serializable<Ciphertext> &self, compr_mode_type compr_mode) {
                      std::ostringstream buffer;
                      self.save(buffer, compr_mode);
                      std::string contents = buffer.str();
                      std::string encoded = b64encode(contents);
                      return encoded;
                  }))
        .function("saveToArray", optional_override([](Serializable<Ciphertext> &self, compr_mode_type compr_mode) {
                      std::ostringstream buffer;
                      self.save(buffer, compr_mode);
                      std::string const contents{ buffer.str() };
                      std::vector<std::uint8_t> const strVector{ contents.begin(), contents.end() };
                      return strVector;
                  }));

    class_<KeyGenerator>("KeyGenerator")
        .constructor<const SEALContext &>()
        .constructor<const SEALContext &, const SecretKey &>()
        .function("secretKey", &KeyGenerator::secret_key)
        .function("createPublicKey", select_overload<void(PublicKey &) const>(&KeyGenerator::create_public_key))
        .function(
            "createPublicKeySerializable",
            select_overload<Serializable<PublicKey>() const>(&KeyGenerator::create_public_key))
        .function("createRelinKeys", select_overload<void(RelinKeys &)>(&KeyGenerator::create_relin_keys))
        .function(
            "createRelinKeysSerializable", select_overload<Serializable<RelinKeys>()>(&KeyGenerator::create_relin_keys))
        .function("createGaloisKeys", optional_override([](KeyGenerator &self, const val &v, GaloisKeys &keys) {
                      // Get the size of the TypedArray input
                      const size_t length = v["length"].as<unsigned>();

                      // If empty, generate all steps.
                      if (length == 0)
                      {
                          self.create_galois_keys(keys);
                          return;
                      }

                      // Create a temporary vector to store the TypedArray values
                      std::vector<std::int32_t> temp;
                      // Resize to the number of elements in the TypedArray
                      temp.resize(length);
                      // Construct a memory view on the temp vector
                      const val memoryView{ typed_memory_view(length, temp.data()) };
                      // Set the data in the vector from the JS side.
                      memoryView.call<void>("set", v);

                      self.create_galois_keys(temp, keys);
                      return;
                  }))
        .function("createGaloisKeysSerializable", optional_override([](KeyGenerator &self, const val &v) {
                      // Get the size of the TypedArray input
                      const size_t length = v["length"].as<unsigned>();

                      // If empty, generate all steps.
                      if (length == 0)
                      {
                          return self.create_galois_keys();
                      }

                      // Create a temporary vector to store the TypedArray values
                      std::vector<std::int32_t> temp;
                      // Resize to the number of elements in the TypedArray
                      temp.resize(length);
                      // Construct a memory view on the temp vector
                      const val memoryView{ typed_memory_view(length, temp.data()) };
                      // Set the data in the vector from the JS side.
                      memoryView.call<void>("set", v);

                      return self.create_galois_keys(temp);
                  }));
    class_<PublicKey>("PublicKey")
        .constructor<>()
        .constructor<PublicKey &&>() // Move via constructor overload
        .function("copy", optional_override([](PublicKey &self, const PublicKey &copy) {
                      self = copy; // Copy via assignment overload
                  }))
        .function("clone", optional_override([](const PublicKey &self) {
                      PublicKey clone = self; // Copy via assignment overload
                      return clone;
                  }))
        .function("move", optional_override([](PublicKey &self, PublicKey &&assign) {
                      // If the original assign was const, this will default to a copy assignment
                      self = std::move(assign);
                  }))
        .function("saveToString", optional_override([](PublicKey &self, compr_mode_type compr_mode) {
                      std::ostringstream buffer;
                      self.save(buffer, compr_mode);
                      std::string contents = buffer.str();
                      std::string encoded = b64encode(contents);
                      return encoded;
                  }))
        .function("saveToArray", optional_override([](PublicKey &self, compr_mode_type compr_mode) {
                      std::ostringstream buffer;
                      self.save(buffer, compr_mode);
                      std::string const contents{ buffer.str() };
                      std::vector<std::uint8_t> const strVector{ contents.begin(), contents.end() };
                      return strVector;
                  }))
        .function(
            "loadFromString", optional_override([](PublicKey &self, SEALContext &context, const std::string &encoded) {
                std::string decoded = b64decode(encoded);
                std::istringstream is(decoded);
                self.load(context, is);
            }))
        .function("loadFromArray", optional_override([](PublicKey &self, SEALContext &context, const val &v) {
                      // Get the size of the TypedArray input
                      const size_t length = v["length"].as<unsigned>();
                      // Create a temporary vector to store the TypedArray values
                      std::vector<std::uint8_t> temp;
                      // Resize to the number of elements in the TypedArray
                      temp.resize(length);
                      // Construct a memory view on the temp vector
                      const val memoryView{ typed_memory_view(length, temp.data()) };
                      // Set the data in the vector from the JS side.
                      memoryView.call<void>("set", v);
                      // Convert the vector into a stringstream
                      std::stringstream ss;
                      // Copy the vector to the stringstream
                      std::copy(temp.begin(), temp.end(), std::ostream_iterator<std::uint8_t>(ss));
                      // Load from the stringstream
                      self.load(context, ss);
                  }));

    class_<SecretKey>("SecretKey")
        .constructor<>()
        .constructor<SecretKey &&>() // Move via constructor overload
        .function("copy", optional_override([](SecretKey &self, const SecretKey &copy) {
                      self = copy; // Copy via assignment overload
                  }))
        .function("clone", optional_override([](const SecretKey &self) {
                      SecretKey clone = self; // Copy via assignment overload
                      return clone;
                  }))
        .function("move", optional_override([](SecretKey &self, SecretKey &&assign) {
                      // If the original assign was const, this will default to a copy assignment
                      self = std::move(assign);
                  }))
        .function("saveToString", optional_override([](SecretKey &self, compr_mode_type compr_mode) {
                      std::ostringstream buffer;
                      self.save(buffer, compr_mode);
                      std::string contents = buffer.str();
                      std::string encoded = b64encode(contents);
                      return encoded;
                  }))
        .function("saveToArray", optional_override([](SecretKey &self, compr_mode_type compr_mode) {
                      std::ostringstream buffer;
                      self.save(buffer, compr_mode);
                      std::string const contents{ buffer.str() };
                      std::vector<std::uint8_t> const strVector{ contents.begin(), contents.end() };
                      return strVector;
                  }))
        .function(
            "loadFromString", optional_override([](SecretKey &self, SEALContext &context, const std::string &encoded) {
                std::string decoded = b64decode(encoded);
                std::istringstream is(decoded);
                self.load(context, is);
            }))
        .function("loadFromArray", optional_override([](SecretKey &self, SEALContext &context, const val &v) {
                      // Get the size of the TypedArray input
                      const size_t length = v["length"].as<unsigned>();
                      // Create a temporary vector to store the TypedArray values
                      std::vector<std::uint8_t> temp;
                      // Resize to the number of elements in the TypedArray
                      temp.resize(length);
                      // Construct a memory view on the temp vector
                      const val memoryView{ typed_memory_view(length, temp.data()) };
                      // Set the data in the vector from the JS side.
                      memoryView.call<void>("set", v);
                      // Convert the vector into a stringstream
                      std::stringstream ss;
                      // Copy the vector to the stringstream
                      std::copy(temp.begin(), temp.end(), std::ostream_iterator<std::uint8_t>(ss));
                      // Load from the stringstream
                      self.load(context, ss);
                  }));

    class_<Plaintext>("Plaintext")
        .constructor<MemoryPoolHandle>()
        .constructor<std::size_t, MemoryPoolHandle>()
        .constructor<std::size_t, std::size_t, MemoryPoolHandle>()
        .function("copy", optional_override([](Plaintext &self, const Plaintext &copy) {
                      self = copy; // Copy via assignment overload
                  }))
        .function("clone", optional_override([](const Plaintext &self) {
                      Plaintext clone = self; // Copy via assignment overload
                      return clone;
                  }))
        .function("move", optional_override([](Plaintext &self, Plaintext &&assign) {
                      // If the original assign was const, this will default to a copy assignment
                      self = std::move(assign);
                  }))
        .function("saveToString", optional_override([](Plaintext &self, compr_mode_type compr_mode) {
                      std::ostringstream buffer;
                      self.save(buffer, compr_mode);
                      std::string contents = buffer.str();
                      std::string encoded = b64encode(contents);
                      return encoded;
                  }))
        .function("saveToArray", optional_override([](Plaintext &self, compr_mode_type compr_mode) {
                      std::ostringstream buffer;
                      self.save(buffer, compr_mode);
                      std::string const contents{ buffer.str() };
                      std::vector<std::uint8_t> const strVector{ contents.begin(), contents.end() };
                      return strVector;
                  }))
        .function(
            "loadFromString", optional_override([](Plaintext &self, SEALContext &context, const std::string &encoded) {
                std::string decoded = b64decode(encoded);
                std::istringstream is(decoded);
                self.load(context, is);
            }))
        .function("loadFromArray", optional_override([](Plaintext &self, SEALContext &context, const val &v) {
                      // Get the size of the TypedArray input
                      const size_t length = v["length"].as<unsigned>();
                      // Create a temporary vector to store the TypedArray values
                      std::vector<std::uint8_t> temp;
                      // Resize to the number of elements in the TypedArray
                      temp.resize(length);
                      // Construct a memory view on the temp vector
                      const val memoryView{ typed_memory_view(length, temp.data()) };
                      // Set the data in the vector from the JS side.
                      memoryView.call<void>("set", v);
                      // Convert the vector into a stringstream
                      std::stringstream ss;
                      // Copy the vector to the stringstream
                      std::copy(temp.begin(), temp.end(), std::ostream_iterator<std::uint8_t>(ss));
                      // Load from the stringstream
                      self.load(context, ss);
                  }))
        .function("reserve", &Plaintext::reserve)
        .function("shrinkToFit", &Plaintext::shrink_to_fit)
        .function("release", optional_override([](Plaintext &self) { return self.release(); }))
        .function("resize", &Plaintext::resize)
        .function("setZero", optional_override([](Plaintext &self) { return self.set_zero(); }))
        .function("isZero", &Plaintext::is_zero)
        .function("capacity", optional_override([](Plaintext &self) { return self.capacity(); }))
        .function("coeffCount", optional_override([](Plaintext &self) { return self.coeff_count(); }))
        .function("significantCoeffCount", &Plaintext::significant_coeff_count)
        .function("nonzeroCoeffCount", &Plaintext::nonzero_coeff_count)
        .function("toPolynomial", &Plaintext::to_string)
        .function("isNttForm", select_overload<bool() const>(&Plaintext::is_ntt_form))
        .function("parmsId", select_overload<parms_id_type &()>(&Plaintext::parms_id))
        .function("scale", select_overload<double &()>(&Plaintext::scale))
        .function(
            "setScale", optional_override([](Plaintext &self, const val &v) { return self.scale() = v.as<double>(); }))
        .function("pool", optional_override([](Plaintext &self) { return self.pool(); }));

    class_<Ciphertext>("Ciphertext")
        .constructor<MemoryPoolHandle>()
        .constructor<const SEALContext &, MemoryPoolHandle>()
        .constructor<const SEALContext &, parms_id_type, MemoryPoolHandle>()
        .constructor<const SEALContext &, parms_id_type, std::size_t, MemoryPoolHandle>()
        .function("copy", optional_override([](Ciphertext &self, const Ciphertext &copy) {
                      self = copy; // Copy via assignment overload
                  }))
        .function("clone", optional_override([](const Ciphertext &self) {
                      Ciphertext clone = self; // Copy via assignment overload
                      return clone;
                  }))
        .function("move", optional_override([](Ciphertext &self, Ciphertext &&assign) {
                      // If the original assign was const, this will default to a copy assignment
                      self = std::move(assign);
                  }))
        .function("saveToString", optional_override([](Ciphertext &self, compr_mode_type compr_mode) {
                      std::ostringstream buffer;
                      self.save(buffer, compr_mode);
                      std::string contents = buffer.str();
                      std::string encoded = b64encode(contents);
                      return encoded;
                  }))
        .function("saveToArray", optional_override([](Ciphertext &self, compr_mode_type compr_mode) {
                      std::ostringstream buffer;
                      self.save(buffer, compr_mode);
                      std::string const contents{ buffer.str() };
                      std::vector<std::uint8_t> const strVector{ contents.begin(), contents.end() };
                      return strVector;
                  }))
        .function(
            "loadFromString", optional_override([](Ciphertext &self, SEALContext &context, const std::string &encoded) {
                std::string decoded = b64decode(encoded);
                std::istringstream is(decoded);
                self.load(context, is);
            }))
        .function("loadFromArray", optional_override([](Ciphertext &self, SEALContext &context, const val &v) {
                      // Get the size of the TypedArray input
                      const size_t length = v["length"].as<unsigned>();
                      // Create a temporary vector to store the TypedArray values
                      std::vector<std::uint8_t> temp;
                      // Resize to the number of elements in the TypedArray
                      temp.resize(length);
                      // Construct a memory view on the temp vector
                      const val memoryView{ typed_memory_view(length, temp.data()) };
                      // Set the data in the vector from the JS side.
                      memoryView.call<void>("set", v);
                      // Convert the vector into a stringstream
                      std::stringstream ss;
                      // Copy the vector to the stringstream
                      std::copy(temp.begin(), temp.end(), std::ostream_iterator<std::uint8_t>(ss));
                      // Load from the stringstream
                      self.load(context, ss);
                  }))
        .function("reserve", optional_override([](Ciphertext &self, const SEALContext &context, std::size_t capacity) {
                      return self.reserve(context, capacity);
                  }))
        .function("resize", optional_override([](Ciphertext &self, std::size_t size) { return self.resize(size); }))
        .function("release", optional_override([](Ciphertext &self) { return self.release(); }))
        .function("coeffModulusSize", optional_override([](Ciphertext &self) { return self.coeff_modulus_size(); }))
        .function("polyModulusDegree", optional_override([](Ciphertext &self) { return self.poly_modulus_degree(); }))
        .function("size", optional_override([](Ciphertext &self) { return self.size(); }))
        .function("sizeCapacity", optional_override([](Ciphertext &self) { return self.size_capacity(); }))
        .function("isTransparent", &Ciphertext::is_transparent)
        .function("isNttForm", select_overload<bool() const>(&Ciphertext::is_ntt_form))
        .function("parmsId", select_overload<parms_id_type &()>(&Ciphertext::parms_id))
        .function("scale", select_overload<double &()>(&Ciphertext::scale))
        .function("correctionFactor", select_overload<double &()>(&Ciphertext::scale))
        .function(
            "setScale", optional_override([](Ciphertext &self, const val &v) { return self.scale() = v.as<double>(); }))
        .function("pool", optional_override([](Ciphertext &self) { return self.pool(); }));

    class_<BatchEncoder>("BatchEncoder")
        .constructor<const SEALContext &>()
        .function(
            "encode",
            optional_override([](BatchEncoder &self, const val &v, Plaintext &destination, const std::string &type) {
                const std::size_t length = v["length"].as<std::size_t>();

                if (type == "INT32")
                {
                    // Create a temporary vector to store the TypedArray values
                    std::vector<std::int32_t> temp;
                    temp.resize(length);

                    // Construct a memory view on the temp vector
                    const val memoryView{ typed_memory_view(length, temp.data()) };
                    // Set the data in the vector from the JS side.
                    memoryView.call<void>("set", v);

                    // Create a new vector that the encode method supports
                    std::vector<std::int64_t> values;
                    copy_vector(temp, values);

                    // Encode the vector to the plainText
                    self.BatchEncoder::encode(values, destination);
                }
                else if (type == "UINT32")
                {
                    // Create a temporary vector to store the TypedArray values
                    std::vector<std::uint32_t> temp;
                    temp.resize(length);

                    // Construct a memory view on the temp vector
                    const val memoryView{ typed_memory_view(length, temp.data()) };
                    // Set the data in the vector from the JS side.
                    memoryView.call<void>("set", v);

                    // Create a new vector that the encode method supports
                    std::vector<std::uint64_t> values;
                    copy_vector(temp, values);

                    // Encode the vector to the plainText
                    self.BatchEncoder::encode(values, destination);
                }
                else if (type == "INT64")
                {
                    std::vector<std::int64_t> values;
                    values.reserve(length);
                    // Right now, embind doesn't support BigInt from JS => WASM
                    // The work arround is to perform string conversion.
                    for (std::size_t i = 0; i < length; ++i)
                    {
                        std::string string_value = v[i].as<std::string>();
                        std::int64_t num_value;
                        string_to_number(string_value, num_value);
                        values.push_back(num_value);
                    }
                    self.BatchEncoder::encode(values, destination);
                }
                else if (type == "UINT64")
                {
                    std::vector<std::uint64_t> values;
                    values.reserve(length);
                    // Right now, embind doesn't support BigInt from JS => WASM
                    // The work arround is to perform string conversion.
                    for (std::size_t i = 0; i < length; ++i)
                    {
                        std::string string_value = v[i].as<std::string>();
                        std::uint64_t num_value;
                        string_to_number(string_value, num_value);
                        values.push_back(num_value);
                    }
                    self.BatchEncoder::encode(values, destination);
                }
            }))
        .function(
            "decodeBigInt", optional_override([](BatchEncoder &self, const Plaintext &plain, const bool &sign,
                                                 MemoryPoolHandle pool = MemoryManager::GetPool()) {
                if (sign)
                {
                    // Reserve the known max encoder slot count
                    const size_t MAX_SLOT_COUNT = self.BatchEncoder::slot_count();

                    // Create a new vector to store the decoded result
                    std::vector<std::int64_t> destination;
                    destination.reserve(MAX_SLOT_COUNT);

                    // Decode the plainText
                    self.BatchEncoder::decode(plain, destination, pool);

                    std::vector<std::string> result_strings;
                    result_strings.reserve(MAX_SLOT_COUNT);

                    for (auto number : destination)
                    {
                        result_strings.push_back(std::to_string(number));
                    }
                    // Create a new array of strings which will be converted
                    // to BigInt64Array on the JS side.
                    emscripten::val result = emscripten::val::array(result_strings.begin(), result_strings.end());
                    return result;
                }
                else
                {
                    // Reserve the known max encoder slot count
                    const size_t MAX_SLOT_COUNT = self.BatchEncoder::slot_count();

                    // Create a new vector to store the decoded result
                    std::vector<std::uint64_t> destination;
                    destination.reserve(MAX_SLOT_COUNT);

                    // Decode the plainText
                    self.BatchEncoder::decode(plain, destination, pool);

                    std::vector<std::string> result_strings;
                    result_strings.reserve(MAX_SLOT_COUNT);

                    for (auto number : destination)
                    {
                        result_strings.push_back(std::to_string(number));
                    }
                    // Create a new array of strings which will be converted
                    // to BigInt64Array on the JS side.
                    emscripten::val result = emscripten::val::array(result_strings.begin(), result_strings.end());
                    return result;
                }
            }))
        .function(
            "decodeInt32", optional_override([](BatchEncoder &self, const Plaintext &plain,
                                                MemoryPoolHandle pool = MemoryManager::GetPool()) {
                // Reserve the known max encoder slot count
                const size_t MAX_SLOT_COUNT = self.BatchEncoder::slot_count();

                // Create a new vector to store the decoded result
                std::vector<std::int64_t> destination;
                destination.reserve(MAX_SLOT_COUNT);

                // Decode the plainText
                self.BatchEncoder::decode(plain, destination, pool);

                // Create a new vector with the type JS can accept
                std::vector<std::int32_t> result;
                copy_vector(destination, result);

                // We must return a vector type instead of a "typed_memory_view"
                // because once this function returns, the c++ vector is
                // garbage collected and the memory view becomes corrupted.
                return result;
            }))
        .function(
            "decodeUint32", optional_override([](BatchEncoder &self, const Plaintext &plain,
                                                 MemoryPoolHandle pool = MemoryManager::GetPool()) {
                // Reserve the known max encoder slot count
                const size_t MAX_SLOT_COUNT = self.BatchEncoder::slot_count();

                // Create a new vector to store the decoded result
                std::vector<std::uint64_t> destination;
                destination.reserve(MAX_SLOT_COUNT);

                // Decode the plainText
                self.BatchEncoder::decode(plain, destination, pool);

                // Create a new vector with the type JS can accept
                std::vector<std::uint32_t> result;
                copy_vector(destination, result);

                // We must return a vector type instead of a "typed_memory_view"
                // because once this function returns, the c++ vector is
                // garbage collected and the memory view becomes corrupted.
                return result;
            }))
        .function("slotCount", optional_override([](BatchEncoder &self) { return self.slot_count(); }));

    class_<CKKSEncoder>("CKKSEncoder")
        .constructor<const SEALContext &>()
        .function(
            "encode", optional_override([](CKKSEncoder &self, const val &v, double scale, Plaintext &destination,
                                           MemoryPoolHandle pool = MemoryManager::GetPool()) {
                // Get the size of the TypedArray input
                const size_t length = v["length"].as<unsigned>();

                // Reserve the known max ckks encoder slot count
                const size_t MAX_SLOT_COUNT = self.CKKSEncoder::slot_count();

                // Create a vector to store the TypedArray values
                std::vector<double> values;
                values.reserve(MAX_SLOT_COUNT);

                // Resize to the number of elements in the TypedArray
                values.resize(length);

                // Construct a memory view on the vector
                const val memoryView{ typed_memory_view(length, values.data()) };
                // Set the data in the vector from the JS side.
                memoryView.call<void>("set", v);

                // Encode the vector to the plainText
                self.CKKSEncoder::encode(values, scale, destination, pool);
            }))
        .function(
            "decodeDouble", optional_override([](CKKSEncoder &self, const Plaintext &plain,
                                                 MemoryPoolHandle pool = MemoryManager::GetPool()) {
                // Create a new vector to store the decoded result
                std::vector<double> destination;

                // Reserve the known max ckks encoder slot count
                const size_t MAX_SLOT_COUNT = self.CKKSEncoder::slot_count();
                destination.reserve(MAX_SLOT_COUNT);

                // Decode the plainText
                self.CKKSEncoder::decode(plain, destination, pool);

                // We must return a vector type instead of a "typed_memory_view"
                // because once this function returns, the c++ vector is
                // garbage collected and the memory view becomes corrupted.
                return destination;
            }))
        .function("slotCount", optional_override([](CKKSEncoder &self) { return self.slot_count(); }));

    class_<MemoryPoolHandle>("MemoryPoolHandle")
        .constructor<>()
        .class_function("MemoryPoolHandleGlobal", &MemoryPoolHandle::Global)
        .class_function("MemoryPoolHandleThreadLocal", &MemoryPoolHandle::ThreadLocal)
        .class_function("MemoryPoolHandleNew", &MemoryPoolHandle::New);

    class_<MemoryManager>("MemoryManager")
        .function("GetPool", select_overload<MemoryPoolHandle(mm_prof_opt_t)>(&MemoryManager::GetPool));

    class_<MMProf>("MMProf");

    class_<MMProfGlobal, base<MMProf>>("MMProfGlobal").function("getPool", &MMProfGlobal::get_pool);

    class_<MMProfNew, base<MMProf>>("MMProfNew").function("getPool", &MMProfNew::get_pool);

    class_<MMProfFixed, base<MMProf>>("MMProfFixed").function("getPool", &MMProfFixed::get_pool);

    class_<MMProfThreadLocal, base<MMProf>>("MMProfThreadLocal").function("getPool", &MMProfThreadLocal::get_pool);

    class_<Encryptor>("Encryptor")
        .constructor<const SEALContext &, const PublicKey &>()
        .constructor<const SEALContext &, const PublicKey &, const SecretKey &>()
        .function("setPublicKey", &Encryptor::set_public_key)
        .function("setSecretKey", &Encryptor::set_secret_key)
        .function(
            "encrypt",
            select_overload<void(const Plaintext &, Ciphertext &, MemoryPoolHandle) const>(&Encryptor::encrypt))
        .function(
            "encryptSerializable",
            select_overload<Serializable<Ciphertext>(const Plaintext &, MemoryPoolHandle) const>(&Encryptor::encrypt))
        .function(
            "encryptSymmetric", select_overload<void(const Plaintext &, Ciphertext &, MemoryPoolHandle) const>(
                                    &Encryptor::encrypt_symmetric))
        .function(
            "encryptSymmetricSerializable",
            select_overload<Serializable<Ciphertext>(const Plaintext &, MemoryPoolHandle) const>(
                &Encryptor::encrypt_symmetric))
        .function("encryptZero", select_overload<void(Ciphertext &, MemoryPoolHandle) const>(&Encryptor::encrypt_zero))
        .function(
            "encryptZeroSerializable",
            select_overload<Serializable<Ciphertext>(MemoryPoolHandle) const>(&Encryptor::encrypt_zero));

    class_<Decryptor>("Decryptor")
        .constructor<const SEALContext &, const SecretKey &>()
        .function("decrypt", &Decryptor::decrypt)
        .function("invariantNoiseBudget", &Decryptor::invariant_noise_budget);

    enum_<scheme_type>("SchemeType")
        .value("none", scheme_type::none)
        .value("bfv", scheme_type::bfv)
        .value("ckks", scheme_type::ckks)
        .value("bgv", scheme_type::bgv);

    // enum_<mm_prof_opt>("mm_prof_opt")
    //     .value("DEFAULT", mm_prof_opt::DEFAULT)
    //     .value("FORCE_GLOBAL", mm_prof_opt::FORCE_GLOBAL)
    //     .value("FORCE_NEW", mm_prof_opt::FORCE_NEW)
    //     .value("FORCE_THREAD_LOCAL", mm_prof_opt::FORCE_THREAD_LOCAL)
    //     ;
}
