#pragma once
#include <vector>

#include "structs/CipherMode.h"
#include "structs/NextMode.h"

class cipher {
public:
	cipher(CipherMode mode); // Конструктор для визначення режиму шифрування
	void Init(std::vector<uint64_t> key, std::vector<uint64_t> iv); // Функція ініціалізації внутрішнього стану (п.7.2)
	void Next(NextMode next_mode = NextMode::normal); // Функція наступного стану (п.7.3)
	uint64_t Strm(); // Функція ключового потоку (п.7.4)
private:
	CipherMode mode;
	uint64_t s[16]; // Змінна стану
	uint64_t r[2]; // Регістри скінченного автомата

	uint64_t FSM(uint64_t x, uint64_t y, uint64_t z); // Функція скінченного автомата CA (п.7.5)
	uint64_t T(uint64_t x); // Функція нелінійної підстановки (п.7.6)
	uint64_t a_mul(uint64_t x); // Множення на alpha в арифметиці поля GF(2^64) (п.7.7)
	uint64_t a_mul_inv(uint64_t x); // Множення на alpha^-1 в арифметиці поля GF(2^64) (п.7.8)
};
