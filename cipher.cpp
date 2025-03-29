#include <iostream>
#include <ostream>

#include "cipher.h"

#include "strumok_tables.h"

cipher::cipher(CipherMode mode) : mode(mode),
                                  r { 0, 0 },
                                  s { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 } {}

void cipher::Init(std::vector<uint64_t> key, std::vector<uint64_t> iv) {
	std::reverse(key.begin(), key.end());
	std::reverse(iv.begin(), iv.end());

	// 1. До 16 комірок регістру зсуву з лінійним зворотним зв'язком
	// заносять значення ключа
	if (mode == CipherMode::strumok256) {
		s[0] = key[3] ^ iv[0];
		s[1] = key[2];
		s[2] = key[1] ^ iv[1];
		s[3] = key[0] ^ iv[2];
		s[4] = key[3];
		s[5] = key[2] ^ iv[3];
		s[6] = ~key[1];
		s[7] = ~key[0];
		s[8] = key[3];
		s[9] = key[2];
		s[10] = ~key[1];
		s[11] = key[0];
		s[12] = key[3];
		s[13] = ~key[2];
		s[14] = key[1];
		s[15] = ~key[0];
	}
	else if (mode == CipherMode::strumok512) {
		s[0] = key[7] ^ iv[0];
		s[1] = key[6];
		s[2] = key[5];
		s[3] = key[4] ^ iv[1];
		s[4] = key[3];
		s[5] = key[2] ^ iv[2];
		s[6] = key[1];
		s[7] = ~key[0];
		s[8] = key[4] ^ iv[3];
		s[9] = ~key[6];
		s[10] = key[5];
		s[11] = ~key[7];
		s[12] = key[3];
		s[13] = key[2];
		s[14] = ~key[1];
		s[15] = key[0];
	}

	r[0] = 0;
	r[1] = 0;

	// 2. Виконують 32 ініціюювальні такти без генерації ключового потоку
	for (uint64_t i = 0; i < 32; ++i) {
		Next(NextMode::init);
	}

	// 3. Розраховують початкове значення змінної стану
	// (виконання функції Next у звичайному режимі)
	Next();
}

void cipher::Next(NextMode next_mode) {
	// Зберігаємо стан перед оновленням
	uint64_t prev_s[16];
	uint64_t prev_r[2];
	std::copy(std::begin(s), std::end(s), std::begin(prev_s));
	std::copy(std::begin(r), std::end(r), std::begin(prev_r));

	// 1. Оновлення r2
	r[1] = T(prev_r[0]);

	// 2. Оновлення r1 (додавання за модулем 2^64)
	r[0] = prev_r[1] + prev_s[13];

	// 3. Зсув регістру зсуву з лінійним зворотним зв'язком вліво
	for (int i = 0; i < 15; ++i) {
		s[i] = prev_s[i + 1];
	}

	// 4. Оновлення 16-ї комірки регістру
	if (next_mode == NextMode::normal) {
		s[15] = a_mul(prev_s[0]) ^ a_mul_inv(prev_s[11]) ^ prev_s[13];
	}
	else {
		s[15] = FSM(prev_s[15], prev_r[0], prev_r[1]) ^ a_mul(prev_s[0]) ^ a_mul_inv(prev_s[11]) ^ prev_s[13];
	}
}

uint64_t cipher::Strm() {
	return FSM(s[15], r[0], r[1]) ^ s[0];
}

uint64_t cipher::FSM(uint64_t x, uint64_t y, uint64_t z) {
	return (x + y) ^ z;
}

uint64_t cipher::T(uint64_t x) {
	return ((strumok_T0[x & 0xff])
		^ (strumok_T1[(x >> 8) & 0xff])
		^ (strumok_T2[(x >> 16) & 0xff])
		^ (strumok_T3[(x >> 24) & 0xff])
		^ (strumok_T4[(x >> 32) & 0xff])
		^ (strumok_T5[(x >> 40) & 0xff])
		^ (strumok_T6[(x >> 48) & 0xff])
		^ (strumok_T7[(x >> 56) & 0xff]));
}

uint64_t cipher::a_mul(uint64_t x) {
	return (((x) << 8) ^ (strumok_alpha_mul[x >> 56]));
}

uint64_t cipher::a_mul_inv(uint64_t x) {
	return (((x) >> 8) ^ (strumok_alphainv_mul[x & 0xff]));
}
