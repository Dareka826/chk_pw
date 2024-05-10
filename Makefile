chk_pw: ./chk_pw.c
	gcc -O2 -lpam -Wall -Wextra -Werror ./chk_pw.c -o ./chk_pw
