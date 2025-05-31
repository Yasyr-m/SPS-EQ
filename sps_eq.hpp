#pragma once

#include <vector>
#include <memory>
#include <random>
#include <libff/algebra/curves/public_params.hpp>
#include <libff/algebra/curves/bls12_381/bls12_381_pp.hpp>
#include <libff/algebra/curves/bls12_381/bls12_381_init.hpp>

namespace sps_eq {

using namespace libff;

// Forward declaration for SigningKey
// (needed for PublicKey constructor)
template<typename ppT>
class SigningKey;

// Структура для подписи SPS-EQ
template<typename ppT>
struct SpsEqSignature {
    using G1 = typename ppT::G1_type;
    using G2 = typename ppT::G2_type;
    using Fr = typename ppT::Fp_type;
    
    G1 Z;
    G1 Y;
    G2 Yp;

    SpsEqSignature() = default;
    SpsEqSignature(const G1& Z, const G1& Y, const G2& Yp) 
        : Z(Z), Y(Y), Yp(Yp) {}

    // Изменение представления подписи и сообщения
    template<typename RNG>
    std::vector<G1> change_repr(std::vector<G1>& messages, RNG& rng) {
        Fr rnd_f = Fr::random_element();
        Fr rnd_u = Fr::random_element();

        // Изменяем подпись
        Z = rnd_u * rnd_f * Z;
        Y = rnd_u.inverse() * Y;
        Yp = rnd_u.inverse() * Yp;

        // Изменяем сообщение
        for (auto& msg : messages) {
            msg = rnd_f * msg;
        }

        return messages;
    }

    // Генерация нового представления подписи и сообщения
    template<typename RNG>
    std::pair<SpsEqSignature<ppT>, std::vector<G1>> generate_new_repr(
        const std::vector<G1>& messages, RNG& rng) {
        Fr rnd_f = Fr::random_element();
        Fr rnd_u = Fr::random_element();

        // Создаем новую подпись
        SpsEqSignature<ppT> new_sig;
        new_sig.Z = rnd_u * rnd_f * Z;
        new_sig.Y = rnd_u.inverse() * Y;
        new_sig.Yp = rnd_u.inverse() * Yp;

        // Создаем новое сообщение
        std::vector<G1> new_messages;
        for (const auto& msg : messages) {
            new_messages.push_back(rnd_f * msg);
        }

        return {new_sig, new_messages};
    }
};

// Структура для публичного ключа
template<typename ppT>
class PublicKey {
public:
    using G1 = typename ppT::G1_type;
    using G2 = typename ppT::G2_type;
    
    size_t signature_capacity;
    std::vector<G2> public_keys;

    PublicKey(size_t capacity);
    PublicKey(const SigningKey<ppT>& sk);
    
    bool verify(const std::vector<G1>& messages, const SpsEqSignature<ppT>& signature) const;
};

// Структура для секретного ключа
template<typename ppT>
class SigningKey {
public:
    using Fr = typename ppT::Fp_type;
    using G1 = typename ppT::G1_type;
    using G2 = typename ppT::G2_type;
    
    size_t signature_capacity;
    std::vector<Fr> secret_keys;

    SigningKey(size_t capacity);
    SigningKey(const std::vector<Fr>& sks);
    
    SpsEqSignature<ppT> sign(const std::vector<G1>& messages) const;

    // Итератор по секретным ключам
    class Iterator {
    public:
        Iterator(const SigningKey<ppT>* sk, size_t index) 
            : sk(sk), index(index) {}
        
        Fr operator*() const { return sk->secret_keys[index]; }
        Iterator& operator++() { ++index; return *this; }
        bool operator!=(const Iterator& other) const { return index != other.index; }
        
    private:
        const SigningKey<ppT>* sk;
        size_t index;
    };

    Iterator begin() const { return Iterator(this, 0); }
    Iterator end() const { return Iterator(this, secret_keys.size()); }
};

} // namespace sps_eq 