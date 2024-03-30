#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <elf.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <assert.h>

#define STACK_SIZE (1024 * 1024)  // 1 MB Stack

extern char **environ;

/**
 * Routine for checking stack made for child program.
 * top_of_stack: stack pointer that will given to child program as %rsp
 * argc: Expected number of arguments
 * argv: Expected argument strings
 */
void stack_check(void* top_of_stack, uint64_t argc, char** argv) {
	printf("----- stack check -----\n");

	assert(((uint64_t)top_of_stack) % 8 == 0);
	printf("top of stack is 8-byte aligned\n");

	uint64_t* stack = top_of_stack;
	uint64_t actual_argc = *(stack++);
	printf("argc: %lu\n", actual_argc);
	assert(actual_argc == argc);

	for (int i = 0; i < argc; i++) {
		char* argp = (char*)*(stack++);
		assert(strcmp(argp, argv[i]) == 0);
		printf("arg %d: %s\n", i, argp);
	}
	// Argument list ends with null pointer
	assert(*(stack++) == 0);

	int envp_count = 0;
	while (*(stack++) != 0)
		envp_count++;

	printf("env count: %d\n", envp_count);

	Elf64_auxv_t* auxv_start = (Elf64_auxv_t*)stack;
	Elf64_auxv_t* auxv_null = auxv_start;
	while (auxv_null->a_type != AT_NULL) {
		auxv_null++;
	}
	printf("aux count: %lu\n", auxv_null - auxv_start);
	printf("----- end stack check -----\n");
}

void load_elf(const char *filepath, Elf64_Addr *entry_point) {
    int fd = open(filepath, O_RDONLY);
    if (fd < 0) {
        perror("Failed to open file");
        exit(EXIT_FAILURE);
    }

    Elf64_Ehdr ehdr;
    if (read(fd, &ehdr, sizeof(ehdr)) != sizeof(ehdr)) {
        perror("Failed to read ELF header");
        exit(EXIT_FAILURE);
    }

    if (memcmp(ehdr.e_ident, ELFMAG, SELFMAG) != 0 || ehdr.e_ident[EI_CLASS] != ELFCLASS64) {
        fprintf(stderr, "Invalid ELF file.\n");
        exit(EXIT_FAILURE);
    }

    *entry_point = ehdr.e_entry;

    Elf64_Phdr phdrs[ehdr.e_phnum];
    lseek(fd, ehdr.e_phoff, SEEK_SET);
    read(fd, phdrs, ehdr.e_phnum * sizeof(Elf64_Phdr));

    for (int i = 0; i < ehdr.e_phnum; ++i) {
        if (phdrs[i].p_type == PT_LOAD) {
            size_t offset = phdrs[i].p_vaddr % sysconf(_SC_PAGESIZE);
            void *segment = mmap((void *)(phdrs[i].p_vaddr - offset), 
                                 phdrs[i].p_memsz + offset, 
                                 PROT_READ | PROT_WRITE | PROT_EXEC, 
                                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
            if (segment == MAP_FAILED) {
                perror("Failed to map segment");
                exit(EXIT_FAILURE);
            }
            lseek(fd, phdrs[i].p_offset, SEEK_SET);
            if (read(fd, segment + offset, phdrs[i].p_filesz) != phdrs[i].p_filesz) {
                perror("Failed to read segment from file");
                exit(EXIT_FAILURE);
            }
            if (phdrs[i].p_memsz > phdrs[i].p_filesz) {
                memset(segment + offset + phdrs[i].p_filesz, 0, phdrs[i].p_memsz - phdrs[i].p_filesz);
            }
        }
    }

    close(fd);
}

void setup_stack_and_transfer_control(char **argv, Elf64_Addr entry_point) {
    char **envp = environ;
    int argc, envc;

    // Calculate argc for argv
    for (argc = 0; argv[argc] != NULL; argc++);
    
    // Calculate envc for envp
    for (envc = 0; envp[envc] != NULL; envc++);

    // Allocate stack for the child process
    unsigned long *stack = mmap(NULL, STACK_SIZE, PROT_READ | PROT_WRITE,
                                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (stack == MAP_FAILED) {
        perror("Failed to allocate stack");
        exit(EXIT_FAILURE);
    }

    unsigned long *stack_top = stack + STACK_SIZE / sizeof(unsigned long);
    // Align stack top to 16-byte boundary
    stack_top = (unsigned long *)((uintptr_t)stack_top & -16L);

    // Start placing items on the stack in reverse order
    
    // Auxiliary vectors
    Elf64_auxv_t *auxv = (Elf64_auxv_t *)(envp + envc + 1); // auxv is after envp
    while (auxv->a_type != AT_NULL) { // Skip to end of auxv
        auxv++;
    }
    // Copy auxiliary vectors in reverse order to the stack
    do {
        auxv--;
        *--stack_top = auxv->a_un.a_val;
        *--stack_top = auxv->a_type;
    } while (auxv->a_type != AT_IGNORE);

    // Terminate envp list
    *--stack_top = 0;

    // Copy environment pointers in reverse order to the stack
    for (int i = envc; i >= 0; i--) {
        *--stack_top = (unsigned long)envp[i];
    }

    // Terminate argv list
    *--stack_top = 0;

    // Copy argument pointers in reverse order to the stack
    for (int i = argc; i >= 0; i--) {
        *--stack_top = (unsigned long)argv[i];
    }

    // Finally, place argc at the very top of the stack
    *--stack_top = argc;

    stack_check(stack_top, argc, argv);
    
    // Transfer control to the child program's entry point
    asm volatile(
        "mov %0, %%rsp\n"
        "xor %%rax, %%rax\n"
        "xor %%rbx, %%rbx\n"
        "xor %%rcx, %%rcx\n"
        "xor %%rdx, %%rdx\n"
        "xor %%rdi, %%rdi\n"
        "xor %%rsi, %%rsi\n"
        "xor %%rbp, %%rbp\n"
        "jmp *%1\n"
        : // No output operands
        : "r"(stack_top), "r"(entry_point)
        : "memory"
    );
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <ELF file>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    Elf64_Addr entry_point;
    load_elf(argv[1], &entry_point);
    setup_stack_and_transfer_control(argv, entry_point);

    // Should never reach here
    return 0;
}
