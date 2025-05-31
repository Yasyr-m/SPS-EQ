# Реализация SPS-EQ

Этот проект реализует схему подписи с сохранением структуры для классов эквивалентности (SPS-EQ) с использованием кривой BLS12-381.

## Возможности

- Генерация ключей
- Подпись сообщений
- Проверка подписи
- Изменение представления подписи
- Генерация нового представления

## Зависимости

- libff (для криптографических примитивов)
- CMake (для сборки)

## Сборка

```bash
mkdir build
cd build
cmake ..
make
```

## Использование

```cpp
#include "sps_eq.hpp"

// Инициализация кривой
ppT::init_public_params();

// Создание ключей
SigningKey<ppT> sk(2);
PublicKey<ppT> pk(sk);

// Создание и подпись сообщений
std::vector<G1> messages = {G1::random_element(), G1::random_element()};
auto signature = sk.sign(messages);

// Проверка подписи
bool is_valid = pk.verify(messages, signature);
```

## Лицензия

Этот проект распространяется под лицензией MIT - подробности в файле LICENSE. 