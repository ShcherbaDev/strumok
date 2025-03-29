#include <iostream>
#include "cipher.h"

void test(CipherMode mode, std::vector<uint64_t> key, std::vector<uint64_t> iv) {
	cipher cipher(mode);
	cipher.Init(key, iv);

	for (int index = 0; index <= 7; index++) {
		std::cout << "Z" << index << ": " << std::hex << cipher.Strm() << '\n';
		cipher.Next();
	}

	std::cout << "====================\n";
}

int main() {
	// Тести для 256-бітового ключа
	std::cout << "\nTESTS FOR 256-bit key:\n\n";

	/*
		1. Вихідні дані ключового потоку:
		Z0:e442d15345dc66ca Z1:f47d700ecc66408a
		Z2:b4cb284b5477e641 Z3:a2afc9092e4124b0
		Z4:728e5fa26b11a7d9 Z5:e6a7b9288c68f972
		Z6:70eb3606de8ba44c Z7:aced7956bd3e3de7
	*/
	test(
		CipherMode::strumok256,
		{ 0x8000000000000000, 0, 0, 0 },
		{ 0, 0, 0, 0 }
	);

	/*
		2. Вихідні дані ключового потоку:
		Z0:a7510b38c7a95d1d Z1:cd5ea28a15b8654f
		Z2:c5e2e2771d0373b2 Z3:98ae829686d5fcee
		Z4:45bddf65c523dbb8 Z5:32a93fcdd950001f
		Z6:752a7fb588af8c51 Z7:9de92736664212d4
	*/
	test(
		CipherMode::strumok256,
		{ 0xaaaaaaaaaaaaaaaa, 0xaaaaaaaaaaaaaaaa, 0xaaaaaaaaaaaaaaaa, 0xaaaaaaaaaaaaaaaa },
		{ 0, 0, 0, 0 }
	);

	/*
		3. Вихідні дані ключового потоку:
		Z0:fe44a2508b5a2acd Z1:af355b4ed21d2742
		Z2:dcd7fdd6a57a9e71 Z3:5d267bd2739fb5eb
		Z4:b22eee96b2832072 Z5:c7de6a4cdaa9a847
		Z6:72d5da93812680f2 Z7:4a0acb7e93da2ce0
	*/
	test(
		CipherMode::strumok256,
		{ 0x8000000000000000, 0000000000000000, 0000000000000000, 0000000000000000 },
		{ 0x0000000000000004, 0x0000000000000003, 0x0000000000000002, 0x0000000000000001 }
	);

	/*
		4. Вихідні дані ключового потоку:
		Z0:e6d0efd9cea5abcd Z1:1e78ba1a9b0e401e
		Z2:bcfbea2c02ba0781 Z3:1bd375588ae08794
		Z4:5493cf21e114c209 Z5:66cd5d7cc7d0e69a
		Z6:a5cdb9f3380d07fa Z7:2940d61a4d4e9ce4
	*/
	test(
		CipherMode::strumok256,
		{ 0xaaaaaaaaaaaaaaaa, 0xaaaaaaaaaaaaaaaa, 0xaaaaaaaaaaaaaaaa, 0xaaaaaaaaaaaaaaaa },
		{ 0x0000000000000004, 0x0000000000000003, 0x0000000000000002, 0x0000000000000001 }
	);

	// Тести для 512-бітового ключа
	std::cout << "\nTESTS FOR 512-bit key:\n\n";

	/*
		1. Вихідні дані ключового потоку:
		Z0:f5b9ab51100f8317 Z1:898ef2086a4af395
		Z2:59571fecb5158d0b Z3:b7c45b6744c71fbb
		Z4:ff2efcf05d8d8db9 Z5:7a585871e5c419c0
		Z6:6b5c4691b9125e71 Z7:a55be7d2b358ec6e
	*/
	test(
		CipherMode::strumok512,
		{ 0x8000000000000000, 0, 0, 0, 0, 0, 0, 0 },
		{ 0, 0, 0, 0 }
	);

	/*
		2. Вихідні дані ключового потоку:
		Z0:f5b9ab51100f8317 Z1:898ef2086a4af395
		Z2:59571fecb5158d0b Z3:b7c45b6744c71fbb
		Z4:ff2efcf05d8d8db9 Z5:7a585871e5c419c0
		Z6:6b5c4691b9125e71 Z7:a55be7d2b358ec6e
	*/
	test(
		CipherMode::strumok512,
		{ 0xaaaaaaaaaaaaaaaa, 0xaaaaaaaaaaaaaaaa, 0xaaaaaaaaaaaaaaaa, 0xaaaaaaaaaaaaaaaa, 0xaaaaaaaaaaaaaaaa, 0xaaaaaaaaaaaaaaaa, 0xaaaaaaaaaaaaaaaa, 0xaaaaaaaaaaaaaaaa },
		{ 0, 0, 0, 0 }
	);

	/*
		3. Вихідні дані ключового потоку:
		Z0:cca12eae8133aaaa Z1:528d85507ce8501d
		Z2:da83c7fe3e1823f1 Z3:21416ebf63b71a42
		Z4:26d76d2bf1a625eb Z5:eec66ee0cd0b1efc
		Z6:02dd68f338a345a8 Z7:47538790a5411adb
	*/
	test(
		CipherMode::strumok512,
		{ 0x8000000000000000, 0, 0, 0, 0, 0, 0, 0 },
		{ 0x0000000000000004, 0x0000000000000003, 0x0000000000000002, 0x0000000000000001 }
	);

	/*
		4. Вихідні дані ключового потоку:
		Z0:965648e775c717d5 Z1:a63c2a7376e92df3
		Z2:0b0eb0bbd47ca267 Z3:ea593d979ae5bd39
		Z4:d773b5e5193cafe1 Z5:b0a26671d259422b
		Z6:85b2aa326b280156 Z7:511ace6451435f0c
	*/
	test(
		CipherMode::strumok512,
		{ 0xaaaaaaaaaaaaaaaa, 0xaaaaaaaaaaaaaaaa, 0xaaaaaaaaaaaaaaaa, 0xaaaaaaaaaaaaaaaa, 0xaaaaaaaaaaaaaaaa, 0xaaaaaaaaaaaaaaaa, 0xaaaaaaaaaaaaaaaa, 0xaaaaaaaaaaaaaaaa },
		{ 0x0000000000000004, 0x0000000000000003, 0x0000000000000002, 0x0000000000000001 }
	);


	return 0;
}
