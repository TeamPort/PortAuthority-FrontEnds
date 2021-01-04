CC:= g++
SRC:= main.cpp
DEBUG:=

gdbfront: $(SRC) ../common/libudis86/libudis86.a
	$(CC) -Ofast -std=c++11 $(SRC) $(DEBUG) -o $@ -lelf -ludis86 -L../common/libudis86 -I. -I../common/ -I../common/rapidjson/include -lpthread

../common/libudis86/libudis86.a: ../common/libudis86/decode.c ../common/libudis86/itab.c ../common/libudis86/syn-att.c ../common/libudis86/syn.c ../common/libudis86/syn-intel.c ../common/libudis86/udis86.c
	gcc -c ../common/libudis86/*.c -fPIC -I.
	ar -cvq ../common/libudis86/libudis86.a *.o
	-@rm *.o

clean:
	-@rm ../common/libudis86/libudis86.a
	-@rm gdbfront
