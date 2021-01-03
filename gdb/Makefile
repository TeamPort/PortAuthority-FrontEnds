CC:= g++
SRC:= main.cpp
DEBUG:=

gdbfront: $(SRC)
	$(CC) -Ofast -lelf -std=c++11 $(SRC) $(DEBUG) -I../common/rapidjson/include -o $@ -pthread

clean:
	-@rm gdbfront
