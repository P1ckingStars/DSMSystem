
all: obj
	g++ -c -g ../src/*.cpp

test1:
	g++ -c -g ../src/*.cpp
	g++ -c -g ../examples/test1.cpp
	g++ *.o ../dependency/librpc.a -o dsmapp
