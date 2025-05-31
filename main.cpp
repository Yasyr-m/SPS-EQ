#include "sps_eq.hpp"
#include <iostream>
#include <vector>
#include <random>

int main() {
    using namespace sps_eq;
    using namespace libff;
    using ppT = bls12_381_pp;
    using Fr = typename ppT::Fp_type;
    using G1 = typename ppT::G1_type;
    using G2 = typename ppT::G2_type;

    // Инициализация кривой
    ppT::init_public_params();

    try {
        // Создаем ключи
        SigningKey<ppT> sk(2);
        PublicKey<ppT> pk(sk);

        // Создаем сообщения
        std::vector<G1> messages = {G1::random_element(), G1::random_element()};

        // Подписываем сообщения
        auto signature = sk.sign(messages);

        // Проверяем подпись
        bool is_valid = pk.verify(messages, signature);
        std::cout << "Signature is " << (is_valid ? "valid" : "invalid") << std::endl;

        // Изменяем представление подписи
        std::random_device rd;
        std::mt19937 gen(rd());
        auto new_messages = signature.change_repr(messages, gen);

        // Проверяем новое представление
        is_valid = pk.verify(new_messages, signature);
        std::cout << "New representation is " << (is_valid ? "valid" : "invalid") << std::endl;

        // Генерируем новое представление
        auto [new_sig, new_msgs] = signature.generate_new_repr(messages, gen);
        is_valid = pk.verify(new_msgs, new_sig);
        std::cout << "Generated new representation is " << (is_valid ? "valid" : "invalid") << std::endl;

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
} 