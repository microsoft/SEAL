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

emscripten::val jsArrayFromVecModulus(const std::vector<Modulus> &vec)
{
    std::vector<uint64_t> res(vec.size());
    std::transform(vec.begin(), vec.end(), res.begin(), [](const Modulus &m) { return m.value(); });
    return emscripten::val::array(res.begin(), res.end());
};

template <typename T>
std::string saveToBase64Helper(const T &self, compr_mode_type mode)
{
    const size_t n = self.save_size(mode);
    std::vector<seal_byte> buf(n);
    const size_t written = self.save(buf.data(), buf.size(), mode);
    return b64encode(buf.data(), written);
}

template <typename T>
emscripten::val saveToArrayHelper(const T &self, compr_mode_type mode)
{
    const size_t n = self.save_size(mode);
    std::vector<uint8_t> buf(n);
    const size_t written = self.save(reinterpret_cast<seal_byte *>(buf.data()), buf.size(), mode);
    emscripten::val ta = emscripten::val::global("Uint8Array").new_(written);
    ta.call<void>("set", emscripten::typed_memory_view(written, buf.data()));
    return ta;
}

template <typename T>
void loadFromBase64Helper(T &self, SEALContext &context, const std::string &encoded)
{
    std::string decoded = b64decode(encoded);
    self.load(context, reinterpret_cast<const seal_byte *>(decoded.data()), decoded.size());
}

template <typename T>
void loadFromArrayHelper(T &self, SEALContext &context, const emscripten::val &data)
{
    const auto ctor = data["constructor"]["name"].as<std::string>();
    if (ctor != "Uint8Array")
    {
        throw std::invalid_argument("expected Uint8Array");
    }
    std::vector<uint8_t> buf = convertJSArrayToNumberVector<uint8_t>(data);
    self.load(context, reinterpret_cast<const seal_byte *>(buf.data()), buf.size());
}

template <typename T>
void loadFromBase64HelperNoContext(T &self, const std::string &encoded)
{
    std::string decoded = b64decode(encoded);
    self.load(reinterpret_cast<const seal_byte *>(decoded.data()), decoded.size());
}

template <typename T>
void loadFromArrayHelperNoContext(T &self, const emscripten::val &data)
{
    const auto ctor = data["constructor"]["name"].as<std::string>();
    if (ctor != "Uint8Array")
    {
        throw std::invalid_argument("expected Uint8Array");
    }
    std::vector<uint8_t> buf = convertJSArrayToNumberVector<uint8_t>(data);
    self.load(reinterpret_cast<const seal_byte *>(buf.data()), buf.size());
}

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

template <class F>
struct y_combinator
{
    F f; // the lambda will be stored here

    // a forwarding operator():
    template <class... Args>
    decltype(auto) operator()(Args &&...args) const
    {
        // we pass ourselves to f, then the arguments. the lambda should take
        // the first argument as `auto&& recurse` or similar.
        return f(*this, std::forward<Args>(args)...);
    }
};
// helper function that deduces the type of the lambda:
template <class F>
y_combinator<std::decay_t<F>> make_y_combinator(F &&f)
{
    return { std::forward<F>(f) };
}

EMSCRIPTEN_BINDINGS(SEAL)
{
    register_vector<Modulus>("VectorModulus");

    emscripten::function("jsArrayFromVecModulus", &jsArrayFromVecModulus);
    emscripten::function("vecFromArrayModulus", &vecFromJSArray<Modulus>);

    class_<util::HashFunction>("UtilHashFunction")
        .class_property("hashBlockUint64Count", &util::HashFunction::hash_block_uint64_count)
        .class_property("hashBlockByteCount", &util::HashFunction::hash_block_byte_count)
        .class_function("hash", optional_override([](const val &v) {
                            const auto ctor = v["constructor"]["name"].as<std::string>();
                            if (ctor != "BigUint64Array")
                            {
                                throw std::invalid_argument("expected BigUint64Array");
                            }
                            std::vector<std::uint64_t> input = convertJSArrayToNumberVector<std::uint64_t>(v);
                            util::HashFunction::hash_block_type result;
                            util::HashFunction::hash(input.data(), input.size(), result);

                            const std::size_t size = result.size();
                            emscripten::val out = emscripten::val::global("BigUint64Array").new_(size);
                            out.call<void>("set", emscripten::typed_memory_view(size, result.data()));
                            return out;
                        }));

    class_<parms_id_type>("ParmsIdType")
        .constructor<>()
        .constructor<parms_id_type &>()
        .function("values", optional_override([](const parms_id_type &self) {
                      const std::size_t size = self.size();
                      emscripten::val ta = emscripten::val::global("BigUint64Array").new_(size);
                      ta.call<void>("set", emscripten::typed_memory_view(size, self.data()));
                      return ta;
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
        .class_function("Create", optional_override([](std::size_t poly_modulus_degree, const val &v) {
                            auto ctor = v["constructor"]["name"].as<std::string>();
                            if (ctor != "Int32Array")
                            {
                                throw std::invalid_argument("expected Int32Array");
                            }
                            auto bit_sizes = convertJSArrayToNumberVector<int32_t>(v);
                            return CoeffModulus::Create(poly_modulus_degree, bit_sizes);
                        }));
    class_<PlainModulus>("PlainModulus")
        .class_function("Batching", select_overload<Modulus(std::size_t, int)>(&PlainModulus::Batching))
        .class_function(
            "BatchingVector", optional_override([](std::size_t poly_modulus_degree, const emscripten::val &v) {
                auto ctor = v["constructor"]["name"].as<std::string>();
                if (ctor != "Int32Array")
                {
                    throw std::invalid_argument("expected Int32Array");
                }
                std::vector<int32_t> bit_sizes = convertJSArrayToNumberVector<int32_t>(v);
                return PlainModulus::Batching(poly_modulus_degree, bit_sizes);
            }));

    class_<Modulus>("Modulus")
        .constructor<std::uint64_t>()
        .function("isZero", &Modulus::is_zero)
        .function("isPrime", &Modulus::is_prime)
        .function("bitCount", &Modulus::bit_count)
        .function("saveToBase64", &saveToBase64Helper<Modulus>)
        .function("saveToArray", &saveToArrayHelper<Modulus>)
        .function("loadFromBase64", &loadFromBase64HelperNoContext<Modulus>)
        .function("loadFromArray", &loadFromArrayHelperNoContext<Modulus>)
        .function("setValue", optional_override([](Modulus &self, uint64_t value) { self = value; }))
        .function("value", &Modulus::value);

    class_<EncryptionParameters>("EncryptionParameters")
        .constructor<scheme_type>()
        .function("setPolyModulusDegree", &EncryptionParameters::set_poly_modulus_degree)
        .function("setCoeffModulus", &EncryptionParameters::set_coeff_modulus)
        .function("setPlainModulus", select_overload<void(const Modulus &)>(&EncryptionParameters::set_plain_modulus))
        .function("scheme", &EncryptionParameters::scheme)
        .function("polyModulusDegree", &EncryptionParameters::poly_modulus_degree)
        .function("coeffModulus", &EncryptionParameters::coeff_modulus)
        .function("plainModulus", &EncryptionParameters::plain_modulus)
        .function("parmsId", &EncryptionParameters::parms_id)
        .function("saveToBase64", &saveToBase64Helper<EncryptionParameters>)
        .function("saveToArray", &saveToArrayHelper<EncryptionParameters>)
        .function("loadFromBase64", &loadFromBase64HelperNoContext<EncryptionParameters>)
        .function("loadFromArray", &loadFromArrayHelperNoContext<EncryptionParameters>);

    class_<EncryptionParameterQualifiers>("EncryptionParameterQualifiers")
        .function("parametersSet", &EncryptionParameterQualifiers::parameters_set)
        .property("usingFFT", &EncryptionParameterQualifiers::using_fft)
        .property("usingNTT", &EncryptionParameterQualifiers::using_ntt)
        .property("usingBatching", &EncryptionParameterQualifiers::using_batching)
        .property("usingFastPlainLift", &EncryptionParameterQualifiers::using_fast_plain_lift)
        .property("usingDescendingModulusChain", &EncryptionParameterQualifiers::using_descending_modulus_chain)
        .property("securityLevel", &EncryptionParameterQualifiers::sec_level);

    class_<std::shared_ptr<const SEALContext::ContextData>>("ContextData")
        .function("parms", optional_override([](std::shared_ptr<const SEALContext::ContextData> &self) {
                      return self->parms();
                  }))
        .function("parmsId", optional_override([](std::shared_ptr<const SEALContext::ContextData> &self) {
                      return self->parms_id();
                  }))
        .function("qualifiers", optional_override([](std::shared_ptr<const SEALContext::ContextData> &self) {
                      return self->qualifiers();
                  }))
        // .function( "totalCoeffModulus",
        //     optional_override([](std::shared_ptr<const
        //     SEALContext::ContextData> &self) { return
        //     self->total_coeff_modulus();
        //     }),
        //     allow_raw_pointers())
        .function(
            "totalCoeffModulusBitCount", optional_override([](std::shared_ptr<const SEALContext::ContextData> &self) {
                return self->total_coeff_modulus_bit_count();
            }))
        // .function( "coeffDivPlainModulus",
        //     optional_override([](std::shared_ptr<const
        //     SEALContext::ContextData> &self) { return
        //     self->coeff_div_plain_modulus();
        //     }),
        //     allow_raw_pointers())
        // .function("baseConverter", &SEALContext::ContextData::base_converter)
        // .function("smallNttTables",
        // &SEALContext::ContextData::small_ntt_tables)
        // .function("plainNttTables",
        // &SEALContext::ContextData::plain_ntt_tables) .function(
        // "plainUpperHalfThreshold", optional_override([](std::shared_ptr<const
        // SEALContext::ContextData> &self) { return
        // self->plain_upper_half_threshold();
        //     }),
        //     allow_raw_pointers())
        // .function( "plainUpperHalfIncrement",
        //     optional_override([](std::shared_ptr<const
        //     SEALContext::ContextData> &self) { return
        //     self->plain_upper_half_increment();
        //     }),
        //     allow_raw_pointers())
        // .function( "upperHalfThreshold",
        //     optional_override([](std::shared_ptr<const
        //     SEALContext::ContextData> &self) { return
        //     self->upper_half_threshold();
        //     }),
        //     allow_raw_pointers())
        // .function( "upperHalfIncrement",
        //     optional_override([](std::shared_ptr<const
        //     SEALContext::ContextData> &self) { return
        //     self->upper_half_increment();
        //     }),
        //     allow_raw_pointers())
        // .function("coeffModPlainModulus",
        // optional_override([](std::shared_ptr<const SEALContext::ContextData>
        // &self)
        // {
        //               return self->coeff_mod_plain_modulus();
        //           }))
        .function("prevContextData", optional_override([](std::shared_ptr<const SEALContext::ContextData> &self) {
                      return self->prev_context_data();
                  }))
        .function("nextContextData", optional_override([](std::shared_ptr<const SEALContext::ContextData> &self) {
                      return self->next_context_data();
                  }))
        .function("chainIndex", optional_override([](std::shared_ptr<const SEALContext::ContextData> &self) {
                      return self->chain_index();
                  }));

    class_<SEALContext>("SEALContext")
        .constructor<const EncryptionParameters &, bool, sec_level_type>()
        .function("assign", optional_override([](SEALContext &self, const SEALContext &copy) { self = copy; }))
        .function("copy", optional_override([](const SEALContext &self) { return SEALContext(self); }))
        .function("toHuman", &printContext)
        .function("getContextData", &SEALContext::get_context_data)
        .function("keyContextData", &SEALContext::key_context_data)
        .function("firstContextData", &SEALContext::first_context_data)
        .function("lastContextData", &SEALContext::last_context_data)
        .function("parametersSet", &SEALContext::parameters_set)
        .function("keyParmsId", &SEALContext::key_parms_id)
        .function("firstParmsId", &SEALContext::first_parms_id)
        .function("lastParmsId", &SEALContext::last_parms_id)
        .function("usingKeyswitching", &SEALContext::using_keyswitching);

    class_<Evaluator>("Evaluator")
        .constructor<const SEALContext &>()
        // Negate
        .function("negate", &Evaluator::negate)
        .function("negateInplace", &Evaluator::negate_inplace)
        // Add
        .function("add", &Evaluator::add)
        .function("addInplace", &Evaluator::add_inplace)
        .function(
            "addPlain",
            optional_override([](Evaluator &self, const Ciphertext &encrypted, const Plaintext &plain,
                                 Ciphertext &destination) { self.add_plain(encrypted, plain, destination); }))
        .function("addPlainWithPool", &Evaluator::add_plain)
        .function(
            "addPlainInplace", optional_override([](Evaluator &self, Ciphertext &encrypted, const Plaintext &plain) {
                self.add_plain_inplace(encrypted, plain);
            }))
        .function("addPlainInplaceWithPool", &Evaluator::add_plain_inplace)
        // Sub
        .function("sub", &Evaluator::sub)
        .function("subInplace", &Evaluator::sub_inplace)
        .function(
            "subPlain",
            optional_override([](Evaluator &self, const Ciphertext &encrypted, const Plaintext &plain,
                                 Ciphertext &destination) { self.sub_plain(encrypted, plain, destination); }))
        .function("subPlainWithPool", &Evaluator::sub_plain)
        .function(
            "subPlainInplace", optional_override([](Evaluator &self, Ciphertext &encrypted, const Plaintext &plain) {
                self.sub_plain_inplace(encrypted, plain);
            }))
        .function("subPlainInplaceWithPool", &Evaluator::sub_plain_inplace)
        // Mul
        .function(
            "multiply",
            optional_override([](Evaluator &self, const Ciphertext &encrypted1, const Ciphertext &encrypted2,
                                 Ciphertext &destination) { self.multiply(encrypted1, encrypted2, destination); }))
        .function("multiplyWithPool", &Evaluator::multiply)
        .function(
            "multiplyInplace",
            optional_override([](Evaluator &self, Ciphertext &encrypted1, const Ciphertext &encrypted2) {
                self.multiply_inplace(encrypted1, encrypted2);
            }))
        .function("multiplyInplaceWithPool", &Evaluator::multiply_inplace)
        .function(
            "multiplyPlain",
            optional_override([](Evaluator &self, const Ciphertext &encrypted, const Plaintext &plain,
                                 Ciphertext &destination) { self.multiply_plain(encrypted, plain, destination); }))
        .function("multiplyPlainWithPool", &Evaluator::multiply_plain)
        .function(
            "multiplyPlainInplace",
            optional_override([](Evaluator &self, Ciphertext &encrypted, const Plaintext &plain) {
                self.multiply_plain_inplace(encrypted, plain);
            }))
        .function("multiplyPlainInplaceWithPool", &Evaluator::multiply_plain_inplace)
        // Square
        .function(
            "square", optional_override([](Evaluator &self, const Ciphertext &encrypted, Ciphertext &destination) {
                self.square(encrypted, destination);
            }))
        .function("squareWithPool", &Evaluator::square)
        .function("squareInplace", optional_override([](Evaluator &self, Ciphertext &encrypted) {
                      self.square_inplace(encrypted);
                  }))
        .function("squareInplaceWithPool", &Evaluator::square_inplace)
        // Exponentiate
        .function(
            "exponentiate", optional_override([](Evaluator &self, const Ciphertext &encrypted, uint64_t exponent,
                                                 const RelinKeys &relin_keys, Ciphertext &destination) {
                self.exponentiate(encrypted, exponent, relin_keys, destination);
            }))
        .function("exponentiateWithPool", &Evaluator::exponentiate)
        .function(
            "exponentiateInplace", optional_override([](Evaluator &self, Ciphertext &encrypted, uint64_t exponent,
                                                        const RelinKeys &relin_keys) {
                self.exponentiate_inplace(encrypted, exponent, relin_keys);
            }))
        .function("exponentiateInplaceWithPool", &Evaluator::exponentiate_inplace)
        // Relinearize
        .function(
            "relinearize",
            optional_override([](Evaluator &self, const Ciphertext &encrypted, const RelinKeys &relin_keys,
                                 Ciphertext &destination) { self.relinearize(encrypted, relin_keys, destination); }))
        .function("relinearizeWithPool", &Evaluator::relinearize)
        .function(
            "relinearizeInplace",
            optional_override([](Evaluator &self, Ciphertext &encrypted, const RelinKeys &relin_keys) {
                self.relinearize_inplace(encrypted, relin_keys);
            }))
        .function("relinearizeInplaceWithPool", &Evaluator::relinearize_inplace)
        // Cipher mod
        .function(
            "cipherModSwitchToNext",
            optional_override([](Evaluator &self, const Ciphertext &cipher, Ciphertext &destination) {
                self.mod_switch_to_next(cipher, destination);
            }))
        .function(
            "cipherModSwitchToNextWithPool",
            select_overload<void(const Ciphertext &, Ciphertext &, MemoryPoolHandle) const>(
                &Evaluator::mod_switch_to_next))
        .function("cipherModSwitchToNextInplace", optional_override([](Evaluator &self, Ciphertext &encrypted) {
                      self.mod_switch_to_next_inplace(encrypted);
                  }))
        .function(
            "cipherModSwitchToNextInplaceWithPool",
            select_overload<void(Ciphertext &, MemoryPoolHandle) const>(&Evaluator::mod_switch_to_next_inplace))
        .function(
            "cipherModSwitchTo",
            optional_override([](Evaluator &self, const Ciphertext &cipher, parms_id_type parms_id,
                                 Ciphertext &destination) { self.mod_switch_to(cipher, parms_id, destination); }))
        .function(
            "cipherModSwitchToWithPool",
            select_overload<void(const Ciphertext &, parms_id_type, Ciphertext &, MemoryPoolHandle) const>(
                &Evaluator::mod_switch_to))
        .function(
            "cipherModSwitchToInplace",
            optional_override([](Evaluator &self, Ciphertext &encrypted, parms_id_type parms_id) {
                self.mod_switch_to_inplace(encrypted, parms_id);
            }))
        .function(
            "cipherModSwitchToInplaceWithPool",
            select_overload<void(Ciphertext &, parms_id_type, MemoryPoolHandle) const>(
                &Evaluator::mod_switch_to_inplace))
        // Plain mod
        .function(
            "plainModSwitchToNext",
            select_overload<void(const Plaintext &, Plaintext &) const>(&Evaluator::mod_switch_to_next))
        .function(
            "plainModSwitchToNextInplace",
            select_overload<void(Plaintext &) const>(&Evaluator::mod_switch_to_next_inplace))
        .function(
            "plainModSwitchTo",
            select_overload<void(const Plaintext &, parms_id_type, Plaintext &) const>(&Evaluator::mod_switch_to))
        .function(
            "plainModSwitchToInplace",
            select_overload<void(Plaintext &, parms_id_type) const>(&Evaluator::mod_switch_to_inplace))

        // Rescale
        .function(
            "rescaleToNext",
            optional_override([](Evaluator &self, const Ciphertext &encrypted, Ciphertext &destination) {
                self.rescale_to_next(encrypted, destination);
            }))
        .function("rescaleToNextWithPool", &Evaluator::rescale_to_next)
        .function("rescaleToNextInplace", optional_override([](Evaluator &self, Ciphertext &encrypted) {
                      self.rescale_to_next_inplace(encrypted);
                  }))
        .function("rescaleToNextInplaceWithPool", &Evaluator::rescale_to_next_inplace)
        .function(
            "rescaleTo",
            optional_override([](Evaluator &self, const Ciphertext &encrypted, parms_id_type parms_id,
                                 Ciphertext &destination) { self.rescale_to(encrypted, parms_id, destination); }))
        .function("rescaleToWithPool", &Evaluator::rescale_to)
        .function(
            "rescaleToInplace", optional_override([](Evaluator &self, Ciphertext &encrypted, parms_id_type parms_id) {
                self.rescale_to_inplace(encrypted, parms_id);
            }))
        .function("rescaleToInplaceWithPool", &Evaluator::rescale_to_inplace)
        // Mod reduce
        .function(
            "modReduceToNext",
            optional_override([](Evaluator &self, const Ciphertext &encrypted, Ciphertext &destination) {
                self.mod_reduce_to_next(encrypted, destination);
            }))
        .function("modReduceToNextWithPool", &Evaluator::mod_reduce_to_next)

        .function("modReduceToNextInplace", optional_override([](Evaluator &self, Ciphertext &encrypted) {
                      self.mod_reduce_to_next_inplace(encrypted);
                  }))
        .function("modReduceToNextInplaceWithPool", &Evaluator::mod_reduce_to_next_inplace)
        .function(
            "modReduceTo",
            optional_override([](Evaluator &self, const Ciphertext &encrypted, parms_id_type parms_id,
                                 Ciphertext &destination) { self.mod_reduce_to(encrypted, parms_id, destination); }))
        .function("modReduceToWithPool", &Evaluator::mod_reduce_to)
        .function(
            "modReduceToInplace", optional_override([](Evaluator &self, Ciphertext &encrypted, parms_id_type parms_id) {
                self.mod_reduce_to_inplace(encrypted, parms_id);
            }))
        .function("modReduceToInplaceWithPool", &Evaluator::mod_reduce_to_inplace)
        // Plain to ntt
        .function(
            "plainTransformToNtt",
            optional_override([](Evaluator &self, const Plaintext &plain, parms_id_type parms_id,
                                 Plaintext &destination) { self.transform_to_ntt(plain, parms_id, destination); }))
        .function(
            "plainTransformToNttWithPool",
            select_overload<void(const Plaintext &, parms_id_type, Plaintext &, MemoryPoolHandle) const>(
                &Evaluator::transform_to_ntt))
        .function(
            "plainTransformToNttInplace",
            optional_override([](Evaluator &self, Plaintext &plain, parms_id_type parms_id) {
                self.transform_to_ntt_inplace(plain, parms_id);
            }))
        .function(
            "plainTransformToNttInplaceWithPool",
            select_overload<void(Plaintext &, parms_id_type, MemoryPoolHandle) const>(
                &Evaluator::transform_to_ntt_inplace))
        // Cipher to ntt
        .function(
            "cipherTransformToNtt",
            select_overload<void(const Ciphertext &, Ciphertext &) const>(&Evaluator::transform_to_ntt))
        .function(
            "cipherTransformToNttInplace",
            select_overload<void(Ciphertext &) const>(&Evaluator::transform_to_ntt_inplace))
        .function(
            "cipherTransformFromNtt",
            select_overload<void(const Ciphertext &, Ciphertext &) const>(&Evaluator::transform_from_ntt))
        .function(
            "cipherTransformFromNttInplace",
            select_overload<void(Ciphertext &) const>(&Evaluator::transform_from_ntt_inplace))
        // Apply Galois
        .function(
            "applyGalois", optional_override([](Evaluator &self, const Ciphertext &encrypted, uint32_t g_elt,
                                                const GaloisKeys &gal_keys, Ciphertext &destination) {
                self.apply_galois(encrypted, g_elt, gal_keys, destination);
            }))
        .function("applyGaloisWithPool", &Evaluator::apply_galois)
        .function(
            "applyGaloisInplace",
            optional_override([](Evaluator &self, Ciphertext &encrypted, uint32_t g_elt, const GaloisKeys &gal_keys) {
                self.apply_galois_inplace(encrypted, g_elt, gal_keys);
            }))
        .function("applyGaloisInplaceWithPool", &Evaluator::apply_galois_inplace)
        // Rotate rows
        .function(
            "rotateRows", optional_override([](Evaluator &self, const Ciphertext &encrypted, int32_t g_elt,
                                               const GaloisKeys &gal_keys, Ciphertext &destination) {
                self.rotate_rows(encrypted, g_elt, gal_keys, destination);
            }))
        .function("rotateRowsWithPool", &Evaluator::rotate_rows)
        .function(
            "rotateRowsInplace",
            optional_override([](Evaluator &self, Ciphertext &encrypted, int32_t g_elt, const GaloisKeys &gal_keys) {
                self.rotate_rows_inplace(encrypted, g_elt, gal_keys);
            }))
        .function("rotateRowsInplaceWithPool", &Evaluator::rotate_rows_inplace)
        // Rotate rows
        .function(
            "rotateColumns",
            optional_override([](Evaluator &self, const Ciphertext &encrypted, const GaloisKeys &gal_keys,
                                 Ciphertext &destination) { self.rotate_columns(encrypted, gal_keys, destination); }))
        .function("rotateColumnsWithPool", &Evaluator::rotate_columns)
        .function(
            "rotateColumnsInplace",
            optional_override([](Evaluator &self, Ciphertext &encrypted, const GaloisKeys &gal_keys) {
                self.rotate_columns_inplace(encrypted, gal_keys);
            }))
        .function("rotateColumnsInplaceWithPool", &Evaluator::rotate_columns_inplace)
        // Rotate vec
        .function(
            "rotateVector", optional_override([](Evaluator &self, const Ciphertext &encrypted, int32_t steps,
                                                 const GaloisKeys &gal_keys, Ciphertext &destination) {
                self.rotate_vector(encrypted, steps, gal_keys, destination);
            }))
        .function("rotateVectorWithPool", &Evaluator::rotate_vector)
        .function(
            "rotateVectorInplace",
            optional_override([](Evaluator &self, Ciphertext &encrypted, int32_t steps, const GaloisKeys &gal_keys) {
                self.rotate_vector_inplace(encrypted, steps, gal_keys);
            }))
        .function("rotateVectorInplaceWithPool", &Evaluator::rotate_vector_inplace)
        // Complex conjugate
        .function(
            "complexConjugate", optional_override([](Evaluator &self, const Ciphertext &encrypted,
                                                     const GaloisKeys &gal_keys, Ciphertext &destination) {
                self.complex_conjugate(encrypted, gal_keys, destination);
            }))
        .function("complexConjugateWithPool", &Evaluator::complex_conjugate)
        .function(
            "complexConjugateInplace",
            optional_override([](Evaluator &self, Ciphertext &encrypted, const GaloisKeys &gal_keys) {
                self.complex_conjugate_inplace(encrypted, gal_keys);
            }))
        .function("complexConjugateInplaceWithPool", &Evaluator::complex_conjugate_inplace);

    class_<KSwitchKeys>("KSwitchKeys")
        .constructor<>()
        .function("size", &KSwitchKeys::size)
        .function("saveToBase64", &saveToBase64Helper<KSwitchKeys>)
        .function("saveToArray", &saveToArrayHelper<KSwitchKeys>)
        .function("loadFromBase64", &loadFromBase64Helper<KSwitchKeys>)
        .function("loadFromArray", &loadFromArrayHelper<KSwitchKeys>);

    class_<RelinKeys, base<KSwitchKeys>>("RelinKeys")
        .constructor<>()
        .function(
            "getIndex", optional_override([](RelinKeys &self, size_t key_power) { return self.get_index(key_power); }))
        .function(
            "hasKey", optional_override([](RelinKeys &self, size_t key_power) { return self.has_key(key_power); }))
        // .function( "key", optional_override([](RelinKeys &self, size_t
        //     key_power) { return self.key(key_power); }))
        .function("assign", optional_override([](RelinKeys &self, const RelinKeys &copy) { self = copy; }))
        .function("copy", optional_override([](const RelinKeys &self) { return RelinKeys(self); }));

    class_<GaloisKeys, base<KSwitchKeys>>("GaloisKeys")
        .constructor<>()
        .function("getIndex", optional_override([](GaloisKeys &self, uint32_t g_elt) { return self.get_index(g_elt); }))
        .function("hasKey", optional_override([](GaloisKeys &self, uint32_t g_elt) { return self.has_key(g_elt); }))
        // .function("key", optional_override([](GaloisKeys &self, uint32_t
        //               g_elt) { return self.key(static_cast<uint64_t>(g_elt));
        //           }))
        .function("assign", optional_override([](GaloisKeys &self, const GaloisKeys &copy) { self = copy; }))
        .function("copy", optional_override([](const GaloisKeys &self) { return GaloisKeys(self); }));
    class_<Serializable<PublicKey>>("SerializablePublicKey")
        .function("saveToBase64", &saveToBase64Helper<Serializable<PublicKey>>)
        .function("saveToArray", &saveToArrayHelper<Serializable<PublicKey>>);
    class_<Serializable<RelinKeys>>("SerializableRelinKeys")
        .function("saveToBase64", &saveToBase64Helper<Serializable<RelinKeys>>)
        .function("saveToArray", &saveToArrayHelper<Serializable<RelinKeys>>);
    class_<Serializable<GaloisKeys>>("SerializableGaloisKeys")
        .function("saveToBase64", &saveToBase64Helper<Serializable<GaloisKeys>>)
        .function("saveToArray", &saveToArrayHelper<Serializable<GaloisKeys>>);
    class_<Serializable<Ciphertext>>("SerializableCiphertext")
        .function("saveToBase64", &saveToBase64Helper<Serializable<Ciphertext>>)
        .function("saveToArray", &saveToArrayHelper<Serializable<Ciphertext>>);

    class_<KeyGenerator>("KeyGenerator")
        .constructor<const SEALContext &>()
        .constructor<const SEALContext &, const SecretKey &>()
        .function("secretKey", &KeyGenerator::secret_key)
        .function("createPublicKey", optional_override([](KeyGenerator &self) {
                      seal::PublicKey pk;
                      self.create_public_key(pk);
                      return pk;
                  }))
        .function(
            "createPublicKeySerializable",
            select_overload<Serializable<PublicKey>() const>(&KeyGenerator::create_public_key))

        .function("createRelinKeys", optional_override([](KeyGenerator &self) {
                      seal::RelinKeys rk;
                      self.create_relin_keys(rk);
                      return rk;
                  }))

        .function(
            "createRelinKeysSerializable", select_overload<Serializable<RelinKeys>()>(&KeyGenerator::create_relin_keys))
        .function("createGaloisKeys", optional_override([](KeyGenerator &self) {
                      seal::GaloisKeys gk;
                      self.create_galois_keys(gk);
                      return gk;
                  }))
        .function("createGaloisKeysWithSteps", optional_override([](KeyGenerator &self, const val &v) {
                      auto ctor = v["constructor"]["name"].as<std::string>();
                      if (ctor != "Int32Array")
                      {
                          throw std::invalid_argument("expected Int32Array");
                      }
                      seal::GaloisKeys gk;
                      std::vector<int32_t> steps = convertJSArrayToNumberVector<int32_t>(v);
                      self.create_galois_keys(steps, gk);
                      return gk;
                  }))
        .function("createGaloisKeysSerializable", optional_override([](KeyGenerator &self) {
                      return self.create_galois_keys();
                  }))
        .function("createGaloisKeysSerializableWithSteps", optional_override([](KeyGenerator &self, const val &v) {
                      auto ctor = v["constructor"]["name"].as<std::string>();
                      if (ctor != "Int32Array")
                      {
                          throw std::invalid_argument("expected Int32Array");
                      }
                      std::vector<int32_t> steps = convertJSArrayToNumberVector<int32_t>(v);
                      return self.create_galois_keys(steps);
                  }));
    class_<PublicKey>("PublicKey")
        .constructor<>()
        .function("assign", optional_override([](PublicKey &self, const PublicKey &copy) { self = copy; }))
        .function("copy", optional_override([](const PublicKey &self) { return PublicKey(self); }))
        .function("saveToBase64", &saveToBase64Helper<PublicKey>)
        .function("saveToArray", &saveToArrayHelper<PublicKey>)
        .function("loadFromBase64", &loadFromBase64Helper<PublicKey>)
        .function("loadFromArray", &loadFromArrayHelper<PublicKey>);

    class_<SecretKey>("SecretKey")
        .constructor<>()
        .function("assign", optional_override([](SecretKey &self, const SecretKey &copy) { self = copy; }))
        .function("copy", optional_override([](const SecretKey &self) { return SecretKey(self); }))
        .function("saveToBase64", &saveToBase64Helper<SecretKey>)
        .function("saveToArray", &saveToArrayHelper<SecretKey>)
        .function("loadFromBase64", &loadFromBase64Helper<SecretKey>)
        .function("loadFromArray", &loadFromArrayHelper<SecretKey>);

    class_<Plaintext>("Plaintext")
        .constructor<>()
        .constructor<std::size_t>()
        .constructor<std::size_t, std::size_t>()
        .class_function("withPool", optional_override([](const MemoryPoolHandle &pool) { return Plaintext(pool); }))
        .class_function(
            "withCoeffCountAndPool", optional_override([](std::size_t coeff_count, const MemoryPoolHandle &pool) {
                return Plaintext(coeff_count, pool);
            }))
        .class_function(
            "withCapAndCoeffCountAndPool",
            optional_override([](std::size_t capacity, std::size_t coeff_count, const MemoryPoolHandle &pool) {
                return Plaintext(capacity, coeff_count, pool);
            }))
        .function("assign", optional_override([](Plaintext &self, const Plaintext &copy) { self = copy; }))
        .function("copy", optional_override([](const Plaintext &self) { return Plaintext(self); }))
        .function("saveToBase64", &saveToBase64Helper<Plaintext>)
        .function("saveToArray", &saveToArrayHelper<Plaintext>)
        .function("loadFromBase64", &loadFromBase64Helper<Plaintext>)
        .function("loadFromArray", &loadFromArrayHelper<Plaintext>)
        .function("reserve", &Plaintext::reserve)
        .function("shrinkToFit", &Plaintext::shrink_to_fit)
        .function("release", &Plaintext::release)
        .function("resize", &Plaintext::resize)
        .function("setZero", optional_override([](Plaintext &self) { self.set_zero(); }))
        .function("isZero", &Plaintext::is_zero)
        .function("capacity", &Plaintext::capacity)
        .function("coeffCount", &Plaintext::coeff_count)
        .function("significantCoeffCount", &Plaintext::significant_coeff_count)
        .function("nonzeroCoeffCount", &Plaintext::nonzero_coeff_count)
        .function("toString", &Plaintext::to_string)
        .function("isNttForm", select_overload<bool() const>(&Plaintext::is_ntt_form))
        .function("parmsId", select_overload<parms_id_type &()>(&Plaintext::parms_id))
        .function("scale", select_overload<double &()>(&Plaintext::scale))
        .function("setScale", optional_override([](Plaintext &self, double scale) { self.scale() = scale; }))
        .function("pool", &Plaintext::pool);

    class_<Ciphertext>("Ciphertext")
        .constructor<>()
        .constructor<const SEALContext &>()
        .constructor<const SEALContext &, parms_id_type>()
        .constructor<const SEALContext &, parms_id_type, std::size_t>()
        .class_function("withPool", optional_override([](MemoryPoolHandle pool) { return Ciphertext(pool); }))
        .class_function("withContextAndPool", optional_override([](const SEALContext &ctx, MemoryPoolHandle pool) {
                            return Ciphertext(ctx, pool);
                        }))
        .class_function(
            "withContextAndParmsIdTypeAndPool",
            optional_override([](const SEALContext &ctx, parms_id_type parms, MemoryPoolHandle pool) {
                return Ciphertext(ctx, parms, pool);
            }))
        .class_function(
            "withContextAndParmsIdTypeAndCapacityAndPool",
            optional_override([](const SEALContext &ctx, parms_id_type parms, std::size_t size_capacity,
                                 MemoryPoolHandle pool) { return Ciphertext(ctx, parms, size_capacity, pool); }))

        .function("assign", optional_override([](Ciphertext &self, const Ciphertext &copy) { self = copy; }))
        .function("copy", optional_override([](const Ciphertext &self) { return Ciphertext(self); }))
        .function("saveToBase64", &saveToBase64Helper<Ciphertext>)
        .function("saveToArray", &saveToArrayHelper<Ciphertext>)
        .function("loadFromBase64", &loadFromBase64Helper<Ciphertext>)
        .function("loadFromArray", &loadFromArrayHelper<Ciphertext>)
        .function("reserve", select_overload<void(const SEALContext &, std::size_t)>(&Ciphertext::reserve))
        .function("resize", select_overload<void(std::size_t)>(&Ciphertext::resize))
        .function("release", &Ciphertext::release)
        .function("coeffModulusSize", &Ciphertext::coeff_modulus_size)
        .function("polyModulusDegree", &Ciphertext::poly_modulus_degree)
        .function("size", &Ciphertext::size)
        .function("sizeCapacity", &Ciphertext::size_capacity)
        .function("isTransparent", &Ciphertext::is_transparent)
        .function("isNttForm", select_overload<bool() const>(&Ciphertext::is_ntt_form))
        .function("parmsId", select_overload<parms_id_type &()>(&Ciphertext::parms_id))
        .function("scale", select_overload<double &()>(&Ciphertext::scale))
        .function("correctionFactor", select_overload<double &()>(&Ciphertext::scale))
        .function("setScale", optional_override([](Ciphertext &self, double scale) { self.scale() = scale; }))
        .function("pool", &Ciphertext::pool);

    class_<BatchEncoder>("BatchEncoder")
        .constructor<const SEALContext &>()
        .function("slotCount", &BatchEncoder::slot_count)
        .function(
            "encode", optional_override([](const BatchEncoder &self, const emscripten::val &v, Plaintext &destination) {
                auto ctor = v["constructor"]["name"].as<std::string>();
                if (ctor == "BigInt64Array")
                {
                    auto values = convertJSArrayToNumberVector<int64_t>(v);
                    self.encode(values, destination);
                }
                else if (ctor == "BigUint64Array")
                {
                    auto values = convertJSArrayToNumberVector<uint64_t>(v);
                    self.encode(values, destination);
                }
                else
                {
                    throw std::invalid_argument("expected one of BigInt64Array, BigUint64Array");
                }
            }))
        .function("decodeBigInt64", optional_override([](const BatchEncoder &self, const Plaintext &plain) {
                      const auto slots = self.slot_count();

                      std::vector<int64_t> dst(slots);
                      self.decode(plain, dst);

                      emscripten::val ta = emscripten::val::global("BigInt64Array").new_(slots);
                      ta.call<void>("set", emscripten::typed_memory_view(slots, dst.data()));
                      return ta;
                  }))
        .function(
            "decodeBigInt64WithPool",
            optional_override([](const BatchEncoder &self, const Plaintext &plain, const MemoryPoolHandle &pool) {
                const auto slots = self.slot_count();

                std::vector<int64_t> dst(slots);
                self.decode(plain, dst, pool);

                emscripten::val ta = emscripten::val::global("BigInt64Array").new_(slots);
                ta.call<void>("set", emscripten::typed_memory_view(slots, dst.data()));
                return ta;
            }))

        .function("decodeBigUint64", optional_override([](const BatchEncoder &self, const Plaintext &plain) {
                      const auto slots = self.slot_count();

                      std::vector<uint64_t> dst(slots);
                      self.decode(plain, dst);

                      emscripten::val ta = emscripten::val::global("BigUint64Array").new_(slots);
                      ta.call<void>("set", emscripten::typed_memory_view(slots, dst.data()));
                      return ta;
                  }))
        .function(
            "decodeBigUint64WithPool",
            optional_override([](const BatchEncoder &self, const Plaintext &plain, const MemoryPoolHandle &pool) {
                const auto slots = self.slot_count();

                std::vector<uint64_t> dst(slots);
                self.decode(plain, dst, pool);

                emscripten::val ta = emscripten::val::global("BigUint64Array").new_(slots);
                ta.call<void>("set", emscripten::typed_memory_view(slots, dst.data()));
                return ta;
            }));

    class_<CKKSEncoder>("CKKSEncoder")
        .constructor<const SEALContext &>()
        .function("slotCount", &CKKSEncoder::slot_count)
        .function(
            "encode", optional_override(
                          [](const CKKSEncoder &self, const emscripten::val &v, double scale, Plaintext &destination) {
                              const auto ctor = v["constructor"]["name"].as<std::string>();
                              if (ctor != "Float64Array")
                              {
                                  throw std::invalid_argument("expected Float64Array");
                              }
                              auto values = convertJSArrayToNumberVector<double>(v);
                              self.encode(values, scale, destination);
                          }))
        .function(
            "encodeWithPool", optional_override([](const CKKSEncoder &self, const emscripten::val &v, double scale,
                                                   Plaintext &destination, const MemoryPoolHandle &pool) {
                const auto ctor = v["constructor"]["name"].as<std::string>();
                if (ctor != "Float64Array")
                {
                    throw std::invalid_argument("expected Float64Array");
                }
                auto values = convertJSArrayToNumberVector<double>(v);
                self.encode(values, scale, destination, pool);
            }))
        .function("decodeFloat64", optional_override([](const CKKSEncoder &self, const Plaintext &plain) {
                      std::vector<double> dst;
                      self.decode(plain, dst);

                      const auto len = dst.size();
                      emscripten::val ta = emscripten::val::global("Float64Array").new_(len);
                      ta.call<void>("set", emscripten::typed_memory_view(len, dst.data()));
                      return ta;
                  }))

        .function(
            "decodeFloat64WithPool",
            optional_override([](const CKKSEncoder &self, const Plaintext &plain, const MemoryPoolHandle &pool) {
                std::vector<double> dst;
                self.decode(plain, dst, pool);

                const auto len = dst.size();
                emscripten::val ta = emscripten::val::global("Float64Array").new_(len);
                ta.call<void>("set", emscripten::typed_memory_view(len, dst.data()));
                return ta;
            }));

    class_<MemoryPoolHandle>("MemoryPoolHandle")
        .constructor<>()
        .class_function("Global", &MemoryPoolHandle::Global)
        .class_function("ThreadLocal", &MemoryPoolHandle::ThreadLocal)
        .class_function("New", &MemoryPoolHandle::New);

    class_<MemoryManager>("MemoryManager")
        .class_function("GetPool", select_overload<MemoryPoolHandle(mm_prof_opt_t)>(&MemoryManager::GetPool));

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
        .function("encrypt", optional_override([](const Encryptor &self, const Plaintext &plain, Ciphertext &cipher) {
                      self.encrypt(plain, cipher);
                  }))
        .function(
            "encryptWithPool",
            select_overload<void(const Plaintext &, Ciphertext &, MemoryPoolHandle) const>(&Encryptor::encrypt))
        .function("encryptSerializable", optional_override([](const Encryptor &self, const Plaintext &plain) {
                      return self.encrypt(plain);
                  }))
        .function(
            "encryptSerializableWithPool",
            select_overload<Serializable<Ciphertext>(const Plaintext &, MemoryPoolHandle) const>(&Encryptor::encrypt))

        .function(
            "encryptSymmetric", optional_override([](const Encryptor &self, const Plaintext &plain,
                                                     Ciphertext &cipher) { self.encrypt_symmetric(plain, cipher); }))
        .function(
            "encryptSymmetricWithPool", select_overload<void(const Plaintext &, Ciphertext &, MemoryPoolHandle) const>(
                                            &Encryptor::encrypt_symmetric))

        .function("encryptSymmetricSerializable", optional_override([](const Encryptor &self, const Plaintext &plain) {
                      return self.encrypt_symmetric(plain);
                  }))
        .function(
            "encryptSymmetricSerializableWithPool",
            select_overload<Serializable<Ciphertext>(const Plaintext &, MemoryPoolHandle) const>(
                &Encryptor::encrypt_symmetric))

        .function("encryptZero", optional_override([](const Encryptor &self, Ciphertext &cipher) {
                      self.encrypt_zero(cipher);
                  }))
        .function(
            "encryptZeroWithPool",
            select_overload<void(Ciphertext &, MemoryPoolHandle) const>(&Encryptor::encrypt_zero))
        .function(
            "encryptZeroSerializable", optional_override([](const Encryptor &self) { return self.encrypt_zero(); }))
        .function(
            "encryptZeroSerializableWithPool",
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
}
