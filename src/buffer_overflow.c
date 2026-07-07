#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define BUFFER_SIZE 256

/**
 * Securely process user input with bounds checking to prevent buffer overflow.
 * 
 * @param input The user input string to process
 * @return 0 on success, -1 on error
 */
int process_input(const char *input) {
    if (input == NULL) {
        fprintf(stderr, "Error: NULL input\n");
        return -1;
    }
    
    size_t input_len = strlen(input);
    if (input_len >= BUFFER_SIZE) {
        fprintf(stderr, "Error: Input too long (%zu >= %d)\n", input_len, BUFFER_SIZE);
        return -1;
    }
    
    char *buffer = malloc(BUFFER_SIZE);
    if (buffer == NULL) {
        fprintf(stderr, "Error: Memory allocation failed\n");
        return -1;
    }
    
    strncpy(buffer, input, BUFFER_SIZE - 1);
    buffer[BUFFER_SIZE - 1] = '\0';
    
    printf("Processed: %s\n", buffer);
    
    // Clear sensitive data before freeing
    memset(buffer, 0, BUFFER_SIZE);
    free(buffer);
    
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <input>\n", argv[0]);
        return 1;
    }
    
    if (process_input(argv[1]) != 0) {
        return 1;
    }
    
    return 0;
}