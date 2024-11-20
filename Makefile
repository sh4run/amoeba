.DEFAULT_GOAL = build                                                                           

CC = gcc
MAKE = make

SRC_DIR = src
INC_DIR = ./h ./message_queue/h ./message_queue/mem-pool/include ./cJSON ./linux-list/include 
OBJ_DIR = obj

SRCS = $(shell find $(SRC_DIR) -name '*.c')
OBJS = $(subst $(SRC_DIR), $(OBJ_DIR), $(SRCS:%.c=%.o))
DEPS = $(OBJS:%.o=%.d)

$(OBJ_DIR):
	mkdir -p $@

INC_FLAGS = $(addprefix -I,$(INC_DIR))

CCFLAGS += -Wall -Wextra -Werror -Wmissing-prototypes -g -Wshadow -Wundef -Wcast-align -Wunreachable-code -O2 -std=c11 -D_GNU_SOURCE

-include $(DEPS)

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c | $(OBJ_DIR)
	$(CC) $(CCFLAGS) $(INC_FLAGS) -MMD -c $< -o $@

cjson = cJSON/cJSON.o
$(cjson):
	$(CC) $(CCFLAGS) -c -o $@ cJSON/cJSON.c

UTILS_INC = ./utils/include
utils = utils/utils.o
$(utils):
	$(CC) $(CCFLAGS) -I$(UTILS_INC) -c -o $@ utils/src/utils.c

INC_FLAGS += -I$(UTILS_INC)

message_queue = message_queue/libmessage_queue.a

$(message_queue):
	@cd message_queue && $(MAKE)

SUBMOD_OBJS = $(message_queue) $(cjson) $(utils)

clean_submod:
	cd message_queue && $(MAKE) clean
	rm -rf $(cjson)
	rm -rf $(utils)

ifeq ($(DYNAMIC),off)
    LDFLAGS = -l:libev.a -l:libmbedcrypto.a
else
    LDFLAGS = -lev -lmbedcrypto
endif

PLATFORM_Linux_LDFLAGS = -lsystemd

LDFLAGS += $(PLATFORM_$(UNAME)_LDFLAGS)

STATIC_LIB = libmessage_queue.a
STATIC_LIB_PATH = message_queue

LDFLAGS += -l:$(STATIC_LIB)

amoeba: $(OBJS) $(SUBMOD_OBJS)
	LIBRARY_PATH=$(STATIC_LIB_PATH) $(CC) $(CCFLAGS) $(OBJS) $(cjson) $(utils) -o $@ $(LDFLAGS)

build: amoeba
	@echo build complete

clean: clean_submod
	rm -rf $(OBJ_DIR)
	rm -rf amoeba
