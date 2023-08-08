#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define COUNT_OF(x) ((sizeof(x)/sizeof(0[x])) / ((size_t)(!(sizeof(x) % sizeof(0[x])))))

typedef struct config_s {
    uint32_t magic;     // +0x00
    uint16_t vid;       // +0x04
    uint16_t did;       // +0x06
    char array[0x10];   // +0x08
} config_t;             // sizeof(config_t) == 0x18

config_t m_cfgs[4];

/**
 * This input_buf is used to populate the module-global m_cfgs structure array.
 */
char input_buf[sizeof(m_cfgs)];

/**
 * This is the known good result that we're looking for.
 *
 * Angr should be used to find a valid input_buf that populates m_cfgs equal to this.
 */
const config_t known_good[4] = {
    {
        .magic = 0xDEADBEEF,
        .vid = 0x8086,
        .did = 0x1337,
        .array = {
            '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
        },
    },
    {
        .magic = 0xDEADBEEF,
        .vid = 0x8086,
        .did = 0x1337,
        .array = {
            'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j',
        },
    },
    {
        .magic = 0xDEADBEEF,
        .vid = 0x8086,
        .did = 0x1337,
        .array = {
            'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J',
        },
    },
    {
        .magic = 0xDEADBEEF,
        .vid = 0x8086,
        .did = 0x1337,
        .array = {
            'Z', 'Y', 'X', 'W', 'V', 'U', 'T', 'S', 'R', 'Q',
        },
    },
};

int main(void)
{
    config_t *pcfg;
    for (int i = 0; i < COUNT_OF(m_cfgs); i++) {
        pcfg = &m_cfgs[i];
        *pcfg = (config_t){
            .magic = 0xDEADBEEF,
            .vid = 0x8086,
            .did = 0x1337,
        };
        memcpy(pcfg->array, input_buf + (i * sizeof(pcfg->array)), sizeof(pcfg->array));
    }
    __asm__(
        "angr_target:        \n\t"
        "   jmp angr_target  \n\t"
    );

    return 0;
}
