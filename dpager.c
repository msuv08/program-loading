#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <elf.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <assert.h>
#include <signal.h>
#include <ucontext.h>

#define STACK_SIZE 20 * sysconf(_SC_PAGE_SIZE)
#define START_ADDR (void *)0xff00000

extern char **environ;

// Struct to hold information about a loadable segment
typedef struct {
    void *segment_start;
    size_t segment_size;
    off_t file_offset;
    size_t file_size;
} ElfSegment;

ElfSegment loadable_segments[128];
size_t num_loadable_segments = 0;

void segfault_handler(int sig, siginfo_t *info, void *unused) {
    // Determine the address that caused the fault
    void *fault_address = info->si_addr;
    size_t page_size = sysconf(_SC_PAGESIZE);
    void *page_start = (void *)((uintptr_t)fault_address & ~(page_size - 1));
    // printf("Page start: %p\n", page_start);
    for (size_t i = 0; i < num_loadable_segments; i++) {
        ElfSegment *seg = &loadable_segments[i];
        if (fault_address >= seg->segment_start && fault_address < (seg->segment_start + seg->segment_size) && seg->file_size > 0) {
            off_t segment_page_offset = (uintptr_t)fault_address - (uintptr_t)seg->segment_start;
            off_t file_page_offset = seg->file_offset + segment_page_offset;

            // Align the file offset to the nearest page boundary
            off_t aligned_file_page_offset = file_page_offset & ~(page_size - 1);

            // Determine the size to read: either a full page or the remainder of the segment.
            size_t size_to_map = page_size;
            if (seg->file_size < segment_page_offset + page_size) {
                size_to_map = seg->file_size - segment_page_offset;
                size_to_map = ((size_to_map + page_size - 1) / page_size) * page_size; // Round up to the nearest page size
            }

            // Attempt to map the page into memory
            void *mapped = mmap(page_start, page_size, PROT_READ | PROT_WRITE | PROT_EXEC,
                                MAP_PRIVATE | MAP_FIXED, 0, aligned_file_page_offset);

            if (mapped == MAP_FAILED) {
                perror("Demand paging failed");
                exit(EXIT_FAILURE);
            }

            // If this page extends beyond the file size, zero the remainder
            if (size_to_map < page_size) {
                memset((char *)mapped + size_to_map, 0, page_size - size_to_map);
            }

            return; // Successfully handled the page fault
        }
    }

    // If the address is not within any loadable segment
    fprintf(stderr, "Segmentation fault at address: %p\n", fault_address);
    exit(EXIT_FAILURE);
}

void setup_signal_handling() {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_flags = SA_SIGINFO;
    sa.sa_sigaction = segfault_handler;
    if (sigaction(SIGSEGV, &sa, NULL) != 0) {
        perror("Failed to setup signal handler");
        exit(EXIT_FAILURE);
    }
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
    // printf("Entry point: %lx\n", *entry_point);

    // Read in the program headers
    Elf64_Phdr phdrs[ehdr.e_phnum];
    lseek(fd, ehdr.e_phoff, SEEK_SET);
    read(fd, phdrs, ehdr.e_phnum * sizeof(Elf64_Phdr));
    
    // Map the segments into memory (if they are loadable)    
    for (int i = 0; i < ehdr.e_phnum; ++i) {
        if (phdrs[i].p_type == PT_LOAD) {
            // Put loadable segments into the array
            ElfSegment *seg = &loadable_segments[num_loadable_segments++];
            // Calculate the offset of the segment within the file
            size_t offset = phdrs[i].p_vaddr % sysconf(_SC_PAGESIZE);
            // Assign the segment information
            seg->segment_start = (void *)phdrs[i].p_vaddr - offset;
            seg->segment_size = phdrs[i].p_memsz + offset;
            seg->file_offset = phdrs[i].p_offset - offset;
            seg->file_size = phdrs[i].p_filesz;
        }
    }
}

void print_stack_image(int argc, char **argv) {
    printf("----- Detailed Stack Image -----\n");

    // Using fixed width for each column
    printf("| %-15s | %-40s |\n", "Address", "Content");
    printf("|-----------------|------------------------------------------|\n");
    
    // Printing argc
    printf("| %-15s | %-40d |\n", "argc", argc);
    
    // Printing argv entries
    for (int i = 0; i < argc; i++) {
        char addrBuffer[17] = {0}; // For holding the address as string
        snprintf(addrBuffer, sizeof(addrBuffer), "argv[%d]", i);
        char contentBuffer[41] = {0}; // For holding the content with a limit
        snprintf(contentBuffer, sizeof(contentBuffer), "%p -> %.30s", (void*)argv[i], argv[i]);
        printf("| %-15s | %-40s |\n", addrBuffer, contentBuffer);
    }
    
    // Marking end of argv
    printf("| %-15s | %-40p |\n", "argv[argc]", (void*)argv[argc]);
    
    // Printing environment variables
    for (int i = 0; environ[i] != NULL; i++) {
        char addrBuffer[17] = {0};
        snprintf(addrBuffer, sizeof(addrBuffer), "env[%d]", i);
        char contentBuffer[41] = {0};
        snprintf(contentBuffer, sizeof(contentBuffer), "%p -> %.30s", (void*)environ[i], environ[i]);
        printf("| %-15s | %-40s |\n", addrBuffer, contentBuffer);
    }

    printf("------------------------------------------------------------\n");
}

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

void setup_stack(void **top_of_stack_ptr, char **argv, Elf64_Addr entry_point) {
    // Get the environment variables
    char **envp = environ;
    int argc, envc, argv_len, envc_len;

    // Calculate envc for envp and envc_len
    for (envc = 0, envc_len = 0; envp[envc] != NULL; envc++) {
        envc_len += strlen(envp[envc]) + 1;
    }

    // Calculate argc for argv and argv_len
    for (argc = 0, argv_len = 0; argv[argc] != NULL; argc++) {
        argv_len += strlen(argv[argc]) + 1;
    }

    // Allocate stack for the child process
    void *stack = mmap(START_ADDR, STACK_SIZE, PROT_READ | PROT_WRITE,
                                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (stack == MAP_FAILED) {
        perror("Failed to allocate stack");
        exit(EXIT_FAILURE);
    }
    // Print out mmap call
    printf("mmap call for stack: mmap(addr: %p, size: %ld)\n", START_ADDR, STACK_SIZE);

    // Set the stack pointer to the top of the stack
    void *stack_top = START_ADDR + STACK_SIZE;
    // Align stack top to 16-byte boundary
    stack_top = (void *)((uintptr_t)stack_top & -16L);

    // Calculate the stack pointer locations for envc and argv
    char *stack_past_envc = (char *)stack_top - envc_len;
    char *stack_past_argv = (char *)stack_past_envc - argv_len;

    // Copy environment strings and pointers in reverse order to the stack
    int envc_ctr = envc - 1;
    while(envp[envc_ctr] != NULL) {
        size_t len = strlen(envp[envc_ctr]) + 1; // Include NULL terminator
        stack_top = ((char *) stack_top) - len;;
        memcpy(stack_top, envp[envc_ctr], len);
        envc_ctr--;
    }

    // Copy argv string and pointer to the stack (only one needed, just one program being loaded)
    size_t len = strlen(argv[argc - 1]) + 1; // Include NULL terminator
    stack_top = ((char *) stack_top) - len;
    memcpy(stack_top, argv[argc - 1], len);

    // Align stack top to 16-byte boundary
    stack_top = (void *)((uint64_t)stack_top & -16L);

    // Iterate through the env variables to find start of AUX vectors
    for(int i = 0; i < envc & *envp!=NULL; i++){
        envp++;
    }
    envp++; // Slide past the NULL terminator
    
    // Find number of AUX vectors
    Elf64_auxv_t *auxv = (Elf64_auxv_t *)envp;
    int aux_num = 0;
    while (auxv[aux_num].a_type != AT_NULL) {
        aux_num++;
    }
    aux_num++;

    // Allocate space for the auxiliary vector, plus one for the AT_NULL terminator
    Elf64_auxv_t *aux_vectors_list = calloc(aux_num + 1, sizeof(Elf64_auxv_t));

    // Copy in the auxiliary vector
    for (int i = 0; i < aux_num; i++) {
        aux_vectors_list[i] = auxv[i];
    }

    // Adjust the stack pointer to make space for the auxiliary vectors
    size_t total_aux_vector_space = aux_num * sizeof(Elf64_auxv_t);
    stack_top = stack_top - total_aux_vector_space;
	
    // Adjust the stack pointer to make space for argc and argv
    size_t total_envc_and_argv_space = argv_len + envc_len;
    stack_top = stack_top - total_envc_and_argv_space;

    // Align stack top to 16-byte boundary
    stack_top = (void *)((uint64_t)stack_top & -16L);
    *top_of_stack_ptr = (void *)stack_top;

    // Load in the argc, argv, envp, and aux vectors
    memcpy(stack_top, &argc, sizeof(argc)); // Copy the value of argc into the stack first
    stack_top += sizeof(argc) * 2; // Align to 8 bits

    // Copy the address of argv into the stack
    memcpy(stack_top, &stack_past_argv, sizeof(stack_past_argv));
    stack_top += sizeof(stack_past_argv) * 2; // Push stack pointer

    // Copy the addresses of envp into the stack
    envc_ctr = 0; // Reset counter from earlier
    while (envc_ctr < envc - 1) {
        // Grab each env variable and copy it to the stack
        memcpy(stack_top, &stack_past_envc, sizeof(stack_past_envc));
        stack_top += sizeof(stack_past_envc);
        envc_ctr++;
    }
    stack_top += sizeof(stack_past_envc); // Push stack pointer

    // Copy the address of the aux vectors into the stack
    memcpy(stack_top, aux_vectors_list, total_aux_vector_space);
    stack_top += total_aux_vector_space; // Push stack pointer

    // Align stack top to 16-byte boundary
    stack_top = (void *)((uint64_t)stack_top & -16L);
    // Finally, run stack check to verify the stack is set up correctly
    stack_check(*top_of_stack_ptr, argc, argv);
    // Print the stack image (debug output)
    // print_stack_image(argc, argv);
}

void transfer_control(void *top_of_stack, Elf64_Addr entry_point) {
    // Transfer control to the entry point
    __asm__ volatile (
        "xor %%rax, %%rax\n\t" // Clear rax
        "xor %%rbx, %%rbx\n\t" // Clear rbx
        "xor %%rcx, %%rcx\n\t" // Clear rcx
        "xor %%rdx, %%rdx\n\t" // Clear rdx
        "mov %0, %%rsp\n\t" // Set up the stack pointer with the desired stack address
        "mov %1, %%rax\n\t" // Move the target address into rax
        "push %%rax\n\t"    // Push the target address onto the stack
        "ret"               // Return, popping the target address off the stack and jumping to it
        :
        : "r" (top_of_stack), "r" (entry_point)
        : "rax", "rbx", "rcx", "rdx", "memory"
    );
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <ELF file>\n", argv[0]);
        exit(EXIT_FAILURE);
    }
    Elf64_Addr entry_point;
    void *top_of_loaded_stack;

    setup_signal_handling(); // Setup signal handler for segfaults
    load_elf(argv[1], &entry_point);
    setup_stack(&top_of_loaded_stack, &argv[1], entry_point);
    transfer_control(top_of_loaded_stack, entry_point);
    
    // SHOULD NOT REACH HERE!!!
    return 0;
}
