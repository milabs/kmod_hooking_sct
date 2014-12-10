NAME		:= scthook

obj-m		:= $(NAME).o
obj-y		:= libudis86/

$(NAME)-y	:= entry.o trace.o \
		   libudis86/built-in.o

ifeq ($(CONFIG_X86_32),y)
$(NAME)-y	+= entry_32.o
endif

ifeq ($(CONFIG_X86_64),y)
$(NAME)-y	+= entry_64.o
endif

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd)

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) clean
