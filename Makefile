CC :=gcc
FLAGS :=-Wall -Wextra 

BUILD_DIR :=build

SRC := $(wildcard *.c)
OBJECTS:=$(SRC:.c=.o)
OBJECTS :=$(addprefix $(BUILD_DIR)/,$(OBJECTS))
TARGET:=netsnoop
all:clean $(TARGET)

$(TARGET):$(OBJECTS)
	$(CC) -o $@ $^

$(BUILD_DIR)/%.o:%.c
	mkdir -p $(BUILD_DIR)
	$(CC) $(FLAGS)  -c $< -o $@

clean: 
	rm -rf $(BUILD_DIR)