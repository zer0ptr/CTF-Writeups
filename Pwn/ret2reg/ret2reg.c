#include <stdio.h>
#include <string.h>
void evilfunction(char *input) {
        char buffer[512];
        strcpy(buffer, input);
}
int main(int argc, char **argv) {
        evilfunction(argv[1]);
        return 0;
}