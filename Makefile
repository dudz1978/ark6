# This is free and unencumbered software released into the public domain.
# 
# Anyone is free to copy, modify, publish, use, compile, sell, or
# distribute this software, either in source code form or as a compiled
# binary, for any purpose, commercial or non-commercial, and by any
# means.
# 
# In jurisdictions that recognize copyright laws, the author or authors
# of this software dedicate any and all copyright interest in the
# software to the public domain. We make this dedication for the benefit
# of the public at large and to the detriment of our heirs and
# successors. We intend this dedication to be an overt act of
# relinquishment in perpetuity of all present and future rights to this
# software under copyright law.
# 
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
# IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
# OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
# ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
# OTHER DEALINGS IN THE SOFTWARE.
# 
# For more information, please refer to <http://unlicense.org/>
# 


all: ./bin/ark6.exe


./bin/ark6.exe: ./bin/io.o ./bin/ark6_functions.o ./bin/hash_functions.o ./bin/ark6_program.o
	gcc -Wall -Wextra -pedantic -O2 -static -s -o $@ $^

./bin/io.o: src/io.c src/include/io.h src/include/ark6_constants.h src/include/hash_functions.h
	gcc -Wall -Wextra -pedantic -O2 -static -s -c -o $@ $<

./bin/ark6_functions.o: src/ark6_functions.c src/include/ark6_constants.h
	gcc -Wall -Wextra -pedantic -O2 -static -s -c -o $@ $<

./bin/hash_functions.o: src/hash_functions.c src/include/ark6_constants.h src/include/ark6_functions.h
	gcc -Wall -Wextra -pedantic -O2 -static -s -c -o $@ $<

./bin/ark6_program.o: src/ark6_program.c src/include/io.h src/include/ark6_constants.h src/include/ark6_functions.h src/include/hash_functions.h
	gcc -Wall -Wextra -pedantic -O2 -static -s -c -o $@ $<

install: ./bin/ark6.exe
	attrib -r -s -h +a C:\Windows\ark6.exe 1> nul 2> nul
	copy /y .\bin\ark6.exe C:\Windows\ 1> nul 2> nul

clean:
	cmd /c "if exist .\bin\*.o del /F /Q .\bin\*.o 2> nul"
	cmd /c "if exist .\bin\ark6.exe del /F /Q .\bin\ark6.exe 2> nul"
