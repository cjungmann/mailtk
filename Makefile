BASEFLAGS = -Wall -Werror -ggdb -DDEBUG
LIB_CFLAGS = ${BASEFLAGS} -I. -fPIC -shared

LIBNAME = mailtk

LOCAL_LINK = -Wl,-R -Wl,. -l${LIBNAME}

MODULES = logging.o socket.o socktalk.o smtp_caps.o smtp.o

# release: LIB_CFLAGS := $( filter-out -ggdb -DDEBUG,$(LIB_CFLAGS) )
# release: lib${LIBNAME}

all : lib${LIBNAME} test_smtp

lib${LIBNAME} : $(MODULES) ${LIBNAME}.h
	$(CC) $(LIB_CFLAGS) -o lib${LIBNAME}.so $(MODULES) -lssl -lcrypto -lcode64

logging.o : logging.c logging.h
	$(CC) $(LIB_CFLAGS) -c -o logging.o logging.c

socket.o : socket.c socket.h
	$(CC) $(LIB_CFLAGS) -c -o socket.o socket.c

socktalk.o : socktalk.c socktalk.h
	$(CC) $(LIB_CFLAGS) -c -o socktalk.o socktalk.c

smtp_caps.o : smtp_caps.c smtp_caps.h
	$(CC) $(LIB_CFLAGS) -c -o smtp_caps.o smtp_caps.c

smtp.o : smtp.c smtp.h
	$(CC) $(LIB_CFLAGS) -c -o smtp.o smtp.c

test_smtp: test_smtp.c lib${LIBNAME}.so
	$(CC) ${BASEFLAGS} -L. -o test_smtp test_smtp.c ${LOCAL_LINK}


clean:
	rm -f *.o *.so logging socket socktalk smtp_caps smtp test_smtp