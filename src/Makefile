ASM     = nasm
LD      = ld

TARGET  = coins
SOURCE  = coins.asm
OBJECT  = coins.o

all: $(TARGET)

$(OBJECT): $(SOURCE)
	$(ASM) -f elf64 $< -o $@

$(TARGET): $(OBJECT)
	$(LD) -pie -static --no-dynamic-linker -z noexecstack -z relro -z now -o $@ $<

clean:
	rm -f $(OBJECT) $(TARGET)

.PHONY: all clean
