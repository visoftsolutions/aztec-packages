#pragma once
#include <crypto/pedersen/generator_data.hpp>
#include <stdlib/hash/pedersen/pedersen.hpp>
#include <stdlib/primitives/witness/witness.hpp>
#include <stdlib/types/circuit_types.hpp>
#include <stdlib/types/convert.hpp>
#include <stdlib/types/native_types.hpp>

namespace aztec3::circuits::abis {

using plonk::stdlib::witness_t;
using plonk::stdlib::types::CircuitTypes;
using plonk::stdlib::types::NativeTypes;
using std::is_same;

template <typename NCT> struct FunctionSignature {
    // typedef typename NCT::address address;
    typedef typename NCT::uint32 uint32;
    typedef typename NCT::boolean boolean;
    typedef typename NCT::grumpkin_point grumpkin_point;
    typedef typename NCT::fr fr;

    uint32 vk_index;
    boolean is_private = false;
    boolean is_constructor = false;

    bool operator==(FunctionSignature<NCT> const&) const = default;

    static FunctionSignature<NCT> empty() { return { 0, 0, 0, 0, 0 }; };

    template <typename Composer> FunctionSignature<CircuitTypes<Composer>> to_circuit_type(Composer& composer) const
    {
        static_assert((std::is_same<NativeTypes, NCT>::value));

        // Capture the composer:
        auto to_ct = [&](auto& e) { return plonk::stdlib::types::to_ct(composer, e); };

        FunctionSignature<CircuitTypes<Composer>> function_signature = {
            to_ct(vk_index),
            to_ct(is_private),
            to_ct(is_constructor),
        };

        return function_signature;
    };

    void set_public()
    {
        static_assert(!(std::is_same<NativeTypes, NCT>::value));

        fr(vk_index).set_public();
        fr(is_private).set_public();
        fr(is_constructor).set_public();
    }

    fr hash() const
    {
        std::vector<fr> inputs = {
            fr(vk_index),
            fr(is_private),
            fr(is_constructor),
        };

        return NCT::compress(inputs, GeneratorIndex::FUNCTION_SIGNATURE);
    }
};

template <typename NCT> void read(uint8_t const*& it, FunctionSignature<NCT>& function_signature)
{
    using serialize::read;

    read(it, function_signature.vk_index);
    read(it, function_signature.is_private);
    read(it, function_signature.is_constructor);
};

template <typename NCT> void write(std::vector<uint8_t>& buf, FunctionSignature<NCT> const& function_signature)
{
    using serialize::write;

    write(buf, function_signature.vk_index);
    write(buf, function_signature.is_private);
    write(buf, function_signature.is_constructor);
};

template <typename NCT> std::ostream& operator<<(std::ostream& os, FunctionSignature<NCT> const& function_signature)
{
    return os << "vk_index: " << function_signature.vk_index << "\n"
              << "is_private: " << function_signature.is_private << "\n"
              << "is_constructor: " << function_signature.is_constructor << "\n";
}

} // namespace aztec3::circuits::abis