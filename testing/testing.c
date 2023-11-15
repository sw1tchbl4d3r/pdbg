#define _DEFAULT_SOURCE

#include <stdio.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <sys/mman.h>

const char P[] = "\
Let's try it with this, a very, very long text of a huge magnitude. Theres no possible way this could be read incorrectly, right? \
Or so I thought. Until I saw that the code segment didnt get read correctly at all. It seems that my little byte reading function was \
up to some irresponsible shenanigans. Inexcusable, is what I would say, if it wasn't me who wrote said function. \
In my defense, we could say that it's Linus' fault for making the PTRACE POKE/PEEK api so damn unusable. \
";

struct packed_things {
    uint8_t p1;
    uint8_t p2;
    uint8_t p3;
    uint8_t p4;
    uint8_t p5;
    uint8_t p6;
    uint8_t p7;
    uint8_t p8;
};

long int3(void) {
    long val;

    asm volatile(
        "mov rax, 1337;"
        "int3;"
        "mov %0, rax;"
        : "=r"(val)
        :
        : "rax"
    );
    
    return val;
}

int dbg_test(void) {
    struct packed_things values;
    values.p1 = 0x41;
    values.p2 = 0x42;
    values.p3 = 0x43;
    values.p4 = 0x44;
    values.p5 = 0x45;
    values.p6 = 0x46;
    values.p7 = 0x47;
    values.p8 = 0x48;

    printf("values.p1 = %d, %p\n", values.p1, &values.p1);
    printf("values.p2 = %d, %p\n", values.p2, &values.p2);
    printf("values.p3 = %d, %p\n", values.p3, &values.p3);
    printf("values.p4 = %d, %p\n", values.p4, &values.p4);
    printf("values.p5 = %d, %p\n", values.p5, &values.p5);
    printf("values.p6 = %d, %p\n", values.p6, &values.p6);
    printf("values.p7 = %d, %p\n", values.p7, &values.p7);
    printf("values.p8 = %d, %p\n", values.p8, &values.p8);
    printf("Paragraph @ %p:\n", P);

    printf("I am %d, and I am waiting...\n", getpid());
    sleep(40);
    printf("Trapping!\n");

    long val = int3();

    printf("Escaped with value: %ld!\n", val);

    printf("values.p1 = %d, %p\n", values.p1, &values.p1);
    printf("values.p2 = %d, %p\n", values.p2, &values.p2);
    printf("values.p3 = %d, %p\n", values.p3, &values.p3);
    printf("values.p4 = %d, %p\n", values.p4, &values.p4);
    printf("values.p5 = %d, %p\n", values.p5, &values.p5);
    printf("values.p6 = %d, %p\n", values.p6, &values.p6);
    printf("values.p7 = %d, %p\n", values.p7, &values.p7);
    printf("values.p8 = %d, %p\n\n", values.p8, &values.p8);

    printf("%s\n", P);
    return 0;
}


int main(void) {
    return dbg_test();
}
