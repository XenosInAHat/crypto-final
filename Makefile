all:
	g++ -std=c++11 atm.cpp -m32 -o atm -lcrypto
	g++ -std=c++11 bank.cpp -m32 -o bank -lpthread -lcrypto
	g++ -std=c++11 proxy.cpp -m32 -o proxy -lpthread
