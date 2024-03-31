#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <elf.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <assert.h>

#define STACK_SIZE 20 * sysconf(_SC_PAGE_SIZE)
#define START_ADDR (void *)0x30000000

extern char **environ;
Elf64_Addr global_e_entry;
Elf64_Addr global_phead_address;
uint16_t global_e_phnum;
uint16_t global_e_phentsize;

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
    // Open the ELF file
    int fd = open(filepath, O_RDONLY);
    if (fd < 0) {
        perror("Failed to open file");
        exit(EXIT_FAILURE);
    }
    // Read in the ELF header
    Elf64_Ehdr ehdr;
    if (read(fd, &ehdr, sizeof(ehdr)) != sizeof(ehdr)) {
        perror("Failed to read ELF header");
        exit(EXIT_FAILURE);
    }
    // Check if the file is a valid ELF file
    if (memcmp(ehdr.e_ident, ELFMAG, SELFMAG) != 0 || ehdr.e_ident[EI_CLASS] != ELFCLASS64) {
        fprintf(stderr, "Invalid ELF file.\n");
        exit(EXIT_FAILURE);
    }
    // Save the entry point
    *entry_point = ehdr.e_entry;
    printf("Entry point: %lx\n", *entry_point);
    // Read in the program headers
    Elf64_Phdr phdrs[ehdr.e_phnum];
    lseek(fd, ehdr.e_phoff, SEEK_SET);
    read(fd, phdrs, ehdr.e_phnum * sizeof(Elf64_Phdr));

    // Save the global variables
    global_e_entry = ehdr.e_entry;
    global_e_phnum = ehdr.e_phnum;
    global_e_phentsize = ehdr.e_phentsize;

    if (ehdr.e_phnum != 0) {
        global_phead_address = (Elf64_Addr)phdrs[0].p_vaddr + ehdr.e_phoff;
    }
    
    // save program header address??

    for (int i = 0; i < ehdr.e_phnum; ++i) {
        if (phdrs[i].p_type == PT_LOAD) {
            // Map the segment into memory (if it is loadable)
            size_t offset = phdrs[i].p_vaddr % sysconf(_SC_PAGESIZE);
            void *segment = mmap((void *)(phdrs[i].p_vaddr - offset), 
                                 phdrs[i].p_memsz + offset, 
                                 PROT_READ | PROT_WRITE | PROT_EXEC, 
                                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
            // Check if mmap was successful
            if (segment == MAP_FAILED) {
                perror("Failed to map segment");
                exit(EXIT_FAILURE);
            }
            // Print out mmap call
            printf("mmap call: mmap(addr: %p, size: %lu)\n", 
                   (void *)(phdrs[i].p_vaddr - offset), 
                   phdrs[i].p_memsz + offset);

            // Load the segment from the file into memory
            lseek(fd, phdrs[i].p_offset, SEEK_SET);
            if (read(fd, segment + offset, phdrs[i].p_filesz) != phdrs[i].p_filesz) {
                perror("Failed to read segment from file");
                exit(EXIT_FAILURE);
            }

            // Zero out the memory region that was not loaded from the file
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

    // Calculate envc for envp
    for (envc = 0; envp[envc] != NULL; envc++);

    // Calculate argc for argv
    for (argc = 0; argv[argc] != NULL; argc++);


    // Allocate stack for the child process
    unsigned long *stack = mmap(START_ADDR, STACK_SIZE, PROT_READ | PROT_WRITE,
                                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (stack == MAP_FAILED) {
        perror("Failed to allocate stack");
        exit(EXIT_FAILURE);
    }

    printf("mmap call for stack: mmap(addr: %p, size: %ld)\n", START_ADDR, STACK_SIZE);
    // Might be a good idea here to zero out the memory after??? Not sure

    unsigned long *stack_top = START_ADDR + STACK_SIZE;
    printf("Stack Top: %p\n", stack_top);
    // Align stack top to 16-byte boundary
    // stack_top = (unsigned long *)((uintptr_t)stack_top & -16L);

    // Copy environment strings and pointers in reverse order to the stack
    printf("envc: %d\n", envc);
    for (int i = envc - 1; i >= 0; i--) {
        size_t len = strlen(envp[i]) + 1; // Include NULL terminator
        stack_top = (unsigned long *)((char *)stack_top - len);
        memcpy(stack_top, envp[i], len);
    }
    printf("Stack Top After envc: %p\n", stack_top);

    // Copy argv strings and pointers in reverse order to the stack
    for (int i = argc - 1; i >= 0; i--) {
        size_t len = strlen(argv[i]) + 1; // Include NULL terminator
        stack_top = (unsigned long *)((char *)stack_top - len);
        memcpy(stack_top, argv[i], len);
    }

    printf("Stack Top after argv: %p\n", stack_top);
    // Align stack top to 16-byte boundary
    stack_top = (void *)((uintptr_t)stack_top & ~0xF);
    printf("Stack Top after alignment: %p\n", stack_top);

    // stack_check(stack_top, argc, argv);
    // Still need to push AUX vectors...

    // Iterate through the env variables to find start of AUX vectors
    for(int i = 0; i < envc & *envp!=NULL; i++){
        envp++;
    }
    envp++;

    printf("envp: %ld\n",(uint64_t)envp);
    
    Elf64_auxv_t *auxv = (Elf64_auxv_t *)envp;
    int aux_num = 0;

    while (auxv[aux_num].a_type != AT_NULL) {
        aux_num++;
    }
    aux_num++;
    
    printf("aux_num: %d\n", aux_num);

    // Allocate space for the auxiliary vector, plus one for the AT_NULL terminator
    Elf64_auxv_t *aux_vectors_list = calloc(aux_num+1, sizeof(Elf64_auxv_t));

    // Copy and modify the auxiliary vector
    for (int i = 0; i < aux_num; i++) {
        aux_vectors_list[i] = auxv[i]; // Shallow copy is sufficient
        switch (aux_vectors_list[i].a_type) {
            case AT_NULL:
                // printf("i: %d\n", i);
                aux_vectors_list[i+1].a_un.a_val = 0;
                aux_vectors_list[i+1].a_type = AT_NULL;
                break;
            case AT_PHNUM:
                aux_vectors_list[i].a_un.a_val = global_e_phnum;
                break;
            case AT_PHENT:
                aux_vectors_list[i].a_un.a_val = global_e_phentsize;
                break;
            case AT_PHDR:
                aux_vectors_list[i].a_un.a_val = (Elf64_Addr)global_phead_address;
                break;
            case AT_ENTRY:
                aux_vectors_list[i].a_un.a_val = global_e_entry;
                break;
            // No default case needed; other types are copied without modification
        }
        // printf("Aux Vector Element %d", i);
        // printf(" Type: %ld\n", aux_vector[i].a_type);
    }
    printf("length of aux_vector: %d\n", aux_num);
    // Adjust the stack pointer to make space for the auxiliary vector
    stack_top = (void *)((uintptr_t)stack_top - (aux_num * sizeof(Elf64_auxv_t)));
    printf("Stack top after adjusting for auxilary vector space: %p\n", stack_top);
    // Adjust the stack pointer to make space for envc
    stack_top = (void *)((uintptr_t)stack_top - (envc * sizeof(uintptr_t)));
    printf("Stack top after envc: %p\n", stack_top);
    // Align stack top to 16-byte boundary
    stack_top = (void *)((uintptr_t)stack_top & ~0xF);


    // // Transfer control to the child program's entry point
    // asm volatile(
    //     "mov %0, %%rsp\n"
    //     "xor %%rax, %%rax\n"
    //     "xor %%rbx, %%rbx\n"
    //     "xor %%rcx, %%rcx\n"
    //     "xor %%rdx, %%rdx\n"
    //     "xor %%rdi, %%rdi\n"
    //     "xor %%rsi, %%rsi\n"
    //     "xor %%rbp, %%rbp\n"
    //     "jmp *%1\n"
    //     : // No output operands
    //     : "r"(stack_top), "r"(entry_point)
    //     : "memory"
    // );
    
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
