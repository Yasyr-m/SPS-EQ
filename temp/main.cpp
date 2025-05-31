#include "sps_eq.hpp"
#include <iostream>
#include <vector>

using namespace sps_eq;
using namespace libff;

int main() {
    // Инициализация кривой BLS12-381
    bls12_381_pp::init_public_params();

    try {
        // Создание ключей
        size_t capacity = 2;
        SigningKey<bls12_381_pp> sk(capacity);
        PublicKey<bls12_381_pp> pk(sk); // Создаем публичный ключ из секретного

        // Создание тестового сообщения
        std::vector<bls12_381_G1> messages;
        for (size_t i = 0; i < capacity; ++i) {
            messages.push_back(bls12_381_G1::random_element());
        }

        // Подписание сообщения
        auto signature = sk.sign(messages);

        // Проверка подписи
        bool is_valid = pk.verify(messages, signature);
        std::cout << "Подпись " << (is_valid ? "валидна" : "невалидна") << std::endl;

        // Тест сериализации публичного ключа
        auto pk_bytes = pk.to_bytes();
        auto pk_deserialized = PublicKey<bls12_381_pp>::from_bytes(pk_bytes);
        
        // Проверка после десериализации публичного ключа
        is_valid = pk_deserialized.verify(messages, signature);
        std::cout << "Подпись после десериализации публичного ключа " 
                  << (is_valid ? "валидна" : "невалидна") << std::endl;

        // Тест сериализации секретного ключа
        auto sk_bytes = sk.to_bytes();
        auto sk_deserialized = SigningKey<bls12_381_pp>::from_bytes(sk_bytes);
        
        // Проверка после десериализации секретного ключа
        auto new_signature = sk_deserialized.sign(messages);
        is_valid = pk.verify(messages, new_signature);
        std::cout << "Подпись после десериализации секретного ключа " 
                  << (is_valid ? "валидна" : "невалидна") << std::endl;

    } catch (const std::exception& e) {
        std::cerr << "Ошибка: " << e.what() << std::endl;
        return 1;
    }

    return 0;
} 