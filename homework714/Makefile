TARGET=sum-nbo
CXXFLAGS=-g

all: $(TARGET)

$(TARGET): sum-nbo.o
	$(LINK.cpp) $^ $(LOADLIBES) $(LDLIBS) -o $@

clean:
	rm -f $(TARGET)
	rm -f *.o

