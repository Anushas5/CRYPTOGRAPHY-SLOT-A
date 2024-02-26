#include <stdio.h>
#include <math.h>

unsigned long long factorial(int n) {
    unsigned long long result = 1;
    for (int i = 2; i <= n; ++i) {
        result *= i;
    }
    return result;
}

int main() {
    int unique_letters = 24;
    unsigned long long total_permutations = factorial(unique_letters);

    printf("Number of possible keys (ignoring identical encryption results): %llu\n", total_permutations);

    unsigned long long effectively_unique_keys = total_permutations / 2; 
    printf("Number of effectively unique keys (considering identical encryption results): %llu\n", effectively_unique_keys);

    int power_of_2 = log2(effectively_unique_keys);
    printf("Number of effectively unique keys expressed as an approximate power of 2: 2^%d\n", power_of_2);

    return 0;
}

