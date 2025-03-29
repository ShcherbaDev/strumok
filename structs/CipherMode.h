#pragma once

// Два режими роботи (п.5.2) для роботи із 256-бітним та 512-бітним ключем
enum class CipherMode {
	strumok256 = 4,
	strumok512 = 8
};
