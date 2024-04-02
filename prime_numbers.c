#include <stdio.h>

int isPrime(int num) {
    for (int i = 2; i <= num / 2; i++) {
        if (num % i == 0) return 0;
    }
    return 1;
}

int main() {
    int count = 0;
    for (int i = 2; i <= 150000; i++) {
        if (isPrime(i)) {
            // printf("%d ", i);
            count++;
        }
    }
    printf("\nTotal Prime Numbers: %d\n", count);
    return 0;
}