/*This header file contains information for the prototype of arguments received in syscall*/

#define __NR_xcrypt 359

typedef struct syscallargs {
        char *input_file;
        char *output_file;
        char *key_buffer;
        int keylength;
        int flags;
}sysargs;
