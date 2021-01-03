CC:= g++
SRC:= main.cpp
DEBUG:=

cfront: $(SRC) libudis86/libudis86.a
	$(CC) -Ofast -std=c++11 $(SRC) $(DEBUG) -o $@ -lelf -ludis86 -Llibudis86 -I. -I../common/rapidjson/include -lpthread


libudis86/libudis86.a: libudis86/decode.c libudis86/itab.c libudis86/syn-att.c libudis86/syn.c libudis86/syn-intel.c libudis86/udis86.c
	gcc -c libudis86/*.c -fPIC -I.
	ar -cvq libudis86/libudis86.a *.o
	-@rm *.o

clean:
	-@rm libudis86/libudis86.a
	-@rm cfront
