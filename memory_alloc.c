#include <stdio.h>
#include <stdlib.h>

int main() {
    int* ptr = (int*)malloc(10 * sizeof(int));
    if (ptr == NULL) {
        printf("Memory allocation failed\n");
        return 1;
    }
    for (int i = 0; i < 10; i++) {
        ptr[i] = i * i;
        printf("%d ", ptr[i]);
    }
    printf("Memory allocated successfully\n");
    printf("\n");
    free(ptr);
    return 0;
}