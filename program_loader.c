#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <elf.h>

#define handle_error(msg) \
    do { perror(msg); exit(EXIT_FAILURE); } while (0)

void load_segment(int fd, Elf64_Phdr *phdr) {
    // Allocate memory for the segment with proper permissions
    void* segment = mmap(NULL, phdr->p_memsz,
                         PROT_READ | PROT_WRITE | PROT_EXEC,
                         MAP_ANONYMOUS | MAP_PRIVATE, 0, 0);
    if (segment == MAP_FAILED) {
        handle_error("mmap");
    }

    // Seek to the segment's position in the file
    if (lseek(fd, phdr->p_offset, SEEK_SET) == -1) {
        handle_error("lseek");
    }

    // Read the segment's contents from the file into the allocated memory
    if (read(fd, segment, phdr->p_filesz) != phdr->p_filesz) {
        handle_error("read");
    }

    // Zero out the remaining part of the allocated memory (BSS section)
    memset((char*)segment + phdr->p_filesz, 0, phdr->p_memsz - phdr->p_filesz);
}


int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <executable>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    int fd = open(argv[1], O_RDONLY);
    if (fd == -1) {
        handle_error("open");
    }

    Elf64_Ehdr ehdr;
    if (read(fd, &ehdr, sizeof(ehdr)) != sizeof(ehdr)) {
        handle_error("read");
    }

    // Validate ELF header
    if (memcmp(ehdr.e_ident, ELFMAG, SELFMAG) != 0 || ehdr.e_ident[EI_CLASS] != ELFCLASS64) {
        fprintf(stderr, "Not a valid ELF file\n");
        exit(EXIT_FAILURE);
    }

    // Seek to the program header table
    if (lseek(fd, ehdr.e_phoff, SEEK_SET) == -1) {
        handle_error("lseek");
    }

    // Load each segment
    for (int i = 0; i < ehdr.e_phnum; ++i) {
        Elf64_Phdr phdr;
        if (read(fd, &phdr, sizeof(phdr)) != sizeof(phdr)) {
            handle_error("read");
        }

        if (phdr.p_type == PT_LOAD) {
            load_segment(fd, &phdr);
        }
    }

    close(fd);

    // Transfer control to the entry point
    void (*entry_point)(void) = (void(*)(void)) ehdr.e_entry;
    entry_point();

    return 0;
}
