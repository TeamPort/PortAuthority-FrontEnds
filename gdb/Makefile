CC:= g++
SRC:= main.cpp
DEBUG:=

gdbfront: $(SRC)
	$(CC) -Ofast -std=c++11 $(SRC) $(DEBUG) -o $@ -pthread

clean:
	-@rm libudis86/libudis86.a
	-@rm cfront
