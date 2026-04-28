CXX = g++
TARGET = netfilter-test
SRC = netfilter-test.cpp
LDLIBS = -lnetfilter_queue

all: $(TARGET)

$(TARGET): $(SRC) iphdr.h tcphdr.h
	$(CXX) -o $(TARGET) $(SRC) $(LDLIBS)

clean:
	rm -f $(TARGET)
