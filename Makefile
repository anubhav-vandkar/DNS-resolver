CXX = g++
CXXFLAGS = -std=c++17 -Wall -O2

LIBS = -ldb_cxx -ldb

SRCS = dns.cpp ./my_folder/root_servers.cpp ./my_folder/utils.cpp

all: 
	$(CXX) $(CXXFLAGS) -o main $(SRCS) $(LIBS)

clean:
	rm -f main