#include "sps_eq.hpp"
#include <random>
#include <stdexcept>
#include <cstring>
#include <iostream>
#include <cassert>

namespace sps_eq {

template<typename ppT>
bool PublicKey<ppT>::verify(const std::vector<G1>& messages, 
                          const SpsEqSignature<ppT>& signature) const {
    if (signature_capacity != messages.size()) {
        return false;
    }

    // Проверка 1: e(m_1, pk_1) * ... * e(m_n, pk_n) = e(Z, Yp)
    auto check1 = ppT::reduced_pairing(messages[0], public_keys[0]);
    for (size_t i = 1; i < messages.size(); ++i) {
        check1 = check1 * ppT::reduced_pairing(messages[i], public_keys[i]);
    }
    
    auto expected_check1 = ppT::reduced_pairing(signature.Z, signature.Yp);
    if (check1 != expected_check1) {
        return false;
    }

    // Проверка 2: e(Y, G2) = e(G1, Yp)
    auto check2 = ppT::reduced_pairing(signature.Y, G2::one());
    auto expected_check2 = ppT::reduced_pairing(G1::one(), signature.Yp);
    
    return check2 == expected_check2;
}

template<typename ppT>
SigningKey<ppT>::SigningKey(size_t capacity) : signature_capacity(capacity) {
    // Генерация случайных секретных ключей
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(1, 1000000);
    
    secret_keys.resize(capacity);
    for (size_t i = 0; i < capacity; ++i) {
        Fr r(dis(gen));
        while (r.is_zero()) {
            r = Fr(dis(gen));
        }
        secret_keys[i] = r;
    }
}

template<typename ppT>
SigningKey<ppT>::SigningKey(const std::vector<Fr>& sks) 
    : signature_capacity(sks.size()), secret_keys(sks) {}

template<typename ppT>
SpsEqSignature<ppT> SigningKey<ppT>::sign(const std::vector<G1>& messages) const {
    using G2 = typename ppT::G2_type;
    if (signature_capacity != messages.size()) {
        throw std::runtime_error("Message size does not match signature capacity");
    }

    // Генерация случайного числа r
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(1, 1000000);
    Fr r(dis(gen));
    while (r.is_zero()) {
        r = Fr(dis(gen));
    }

    // Вычисление Z = r * (sk_1 * m_1 + ... + sk_n * m_n)
    G1 Z = G1::zero();
    for (size_t i = 0; i < messages.size(); ++i) {
        Z = Z + (secret_keys[i] * messages[i]);
    }
    Z = r * Z;

    // Вычисление Y = r^(-1) * G1
    G1 Y = r.inverse() * G1::one();

    // Вычисление Yp = r^(-1) * G2
    G2 Yp = r.inverse() * G2::one();

    return SpsEqSignature<ppT>(Z, Y, Yp);
}

template<typename ppT>
PublicKey<ppT>::PublicKey(size_t capacity) : signature_capacity(capacity) {
    public_keys.resize(capacity);
}

template<typename ppT>
PublicKey<ppT>::PublicKey(const SigningKey<ppT>& sk) : signature_capacity(sk.signature_capacity) {
    public_keys.resize(signature_capacity);
    for (size_t i = 0; i < signature_capacity; ++i) {
        public_keys[i] = sk.secret_keys[i] * G2::one();
    }
}

// Явное инстанцирование для BLS12-381
template class PublicKey<libff::bls12_381_pp>;
template class SigningKey<libff::bls12_381_pp>;
template struct SpsEqSignature<libff::bls12_381_pp>;

} // namespace sps_eq

// Тесты
void run_tests() {
    using namespace sps_eq;
    using namespace libff;
    using ppT = bls12_381_pp;
    using Fr = typename ppT::Fp_type;
    using G1 = typename ppT::G1_type;
    using G2 = typename ppT::G2_type;

    std::cout << "Running tests...\n";

    // Тест 1: Создание ключей
    {
        size_t capacity = 2;
        SigningKey<ppT> sk(capacity);
        assert(sk.signature_capacity == capacity);
        assert(sk.secret_keys.size() == capacity);

        std::vector<Fr> secret_keys = {Fr::one(), Fr::one(), Fr::one()};
        SigningKey<ppT> sk2(secret_keys);
        assert(sk2.signature_capacity == 3);
        assert(sk2.secret_keys.size() == 3);
    }

    // Тест 2: Итератор по ключам
    {
        SigningKey<ppT> sk(std::vector<Fr>{Fr::one(), Fr::one(), Fr::one()});
        for (const auto& key : sk) {
            assert(key == Fr::one());
        }
    }

    // Тест 3: Подпись и верификация
    {
        SigningKey<ppT> sk(2);
        PublicKey<ppT> pk(sk);

        std::vector<G1> messages = {G1::random_element(), G1::random_element()};
        auto signature = sk.sign(messages);

        assert(pk.verify(messages, signature));

        std::vector<G1> different_messages = {G1::random_element(), G1::random_element()};
        assert(!pk.verify(different_messages, signature));
    }

    // Тест 4: Изменение представления подписи
    {
        SigningKey<ppT> sk(2);
        PublicKey<ppT> pk(sk);

        std::vector<G1> messages = {G1::random_element(), G1::random_element()};
        auto signature = sk.sign(messages);

        // Изменяем представление
        std::random_device rd;
        std::mt19937 gen(rd());
        auto new_messages = signature.change_repr(messages, gen);

        // Проверяем, что новая подпись валидна для нового сообщения
        assert(pk.verify(new_messages, signature));

        // Генерируем новое представление
        auto [new_sig, new_msgs] = signature.generate_new_repr(messages, gen);
        assert(pk.verify(new_msgs, new_sig));
    }

    std::cout << "All tests passed!\n";
} 