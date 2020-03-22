BASEFLAGS = -Wall -Werror -ggdb -DDEBUG
LIB_CFLAGS = ${BASEFLAGS} -I. -fPIC -shared

LIBNAME = mailtk

LOCAL_LINK = -Wl,-R -Wl,. -l${LIBNAME}

MODULES = linedrop.o logging.o socket.o socktalk.o smtp_caps.o smtp_iact.o

# release: LIB_CFLAGS := $( filter-out -ggdb -DDEBUG,$(LIB_CFLAGS) )
# release: lib${LIBNAME}

all : lib${LIBNAME}.so

lib${LIBNAME}.so : $(MODULES) ${LIBNAME}.h
	$(CC) $(LIB_CFLAGS) -o lib${LIBNAME}.so $(MODULES) -lssl -lcrypto -lcode64

linedrop.o : linedrop.c linedrop.h
	$(CC) $(LIB_CFLAGS) -c -l linedrop.o linedrop.c

logging.o : logging.c logging.h
	$(CC) $(LIB_CFLAGS) -c -o logging.o logging.c

socket.o : socket.c socket.h
	$(CC) $(LIB_CFLAGS) -c -o socket.o socket.c

socktalk.o : socktalk.c socktalk.h
	$(CC) $(LIB_CFLAGS) -c -o socktalk.o socktalk.c

smtp_caps.o : smtp_caps.c smtp_caps.h
	$(CC) $(LIB_CFLAGS) -c -o smtp_caps.o smtp_caps.c

smtp_iact.o : smtp_iact.c smtp_iact.h
	$(CC) $(LIB_CFLAGS) -c -o smtp_iact.o smtp_iact.c


clean:
	rm -f *.o *.so linedrop logging socket socktalk smtp_caps smtp smtp_iact smtp_send
