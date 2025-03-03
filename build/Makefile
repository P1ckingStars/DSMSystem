all: 
	g++ -fno-stack-protector -I ../src/include -c ../src/lib/*.cpp ../src/lib/threadlib/*.cpp ../src/lib/util/*.cpp ../src/lib/*.s ../examples/test1.cpp
	g++ -I ../src/include -T ../linker.ld ./*.o ../dependency/rpc.a
