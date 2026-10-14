CXX      = g++
CXXFLAGS = -std=c++17 -Wall -Wextra -O2
LDLIBS   = -lssl -lcrypto

sikradio: sikradio.o
	$(CXX) $(CXXFLAGS) -o sikradio sikradio.o $(LDLIBS)

sikradio.o: sikradio.cpp
	$(CXX) $(CXXFLAGS) -c sikradio.cpp

clean:
	rm -f sikradio sikradio.o

.PHONY: clean
