
# PPEDUMP => Portable Portable Executable Dump ;)
BIN_TARGET = ppedump

SRC_FILES  = portable_pe_dump.cpp cxx_demangle.cpp
OBJ_FILES  = $(patsubst %.cpp, %.o, $(SRC_FILES))

DEFINES    = -DCOLOR_PRINT
CXXFLAGS   = $(DEFINES) -std=c++11 -Wall -Wextra -Weffc++ -pedantic -Wno-unused-function

#############################

all: $(BIN_TARGET)
	strip $(BIN_TARGET)

$(BIN_TARGET): $(OBJ_FILES)
	$(CXX) $(CXXFLAGS) -o $(BIN_TARGET) $(OBJ_FILES)

$(OBJ_FILES): %.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	rm -f $(BIN_TARGET)
	rm -f *.o

