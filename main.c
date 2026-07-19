#include <stdio.h>
#include <string.h>

int main() {
    char buffer[100];
    printf("Enter some text: ");
    if (fgets(buffer, sizeof(buffer), stdin)!= NULL) {  // Use fgets to prevent buffer overflow
        // Remove the newline character if present
        size_t len = strlen(buffer);
        if (len > 0 && buffer[len - 1] == '\n') {
            buffer[len - 1] = '\0';
        }
        printf("You entered: %s\n", buffer);
    } else {
        fprintf(stderr, "Error reading input.\n");
        return 1;
    }
    return 0;
}