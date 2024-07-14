// main.c

#if _WINDOWS
#include <windows.h>
#endif
#include <stdio.h>
#include <pcode_wrapper.h>
#include <stdlib.h>

#if _WINDOWS
#define malloc(size) HeapAlloc(GetProcessHeap(), 0, size)
#endif

unsigned char *readSlaFile(const char *path, size_t *size)
{
    FILE *file = fopen(path, "rb");
    if (!file)
    {
        return NULL;
    }

    fseek(file, 0, SEEK_END);
    *size = ftell(file);
    fseek(file, 0, SEEK_SET);

    unsigned char *buffer = (unsigned char *)malloc(*size);
    if (!buffer)
    {
        fclose(file);
        return NULL;
    }

    size_t r = fread(buffer, 1, *size, file);

    if (r != *size)
    {
        free(buffer);
        fclose(file);
        return NULL;
    }

    fclose(file);

    return buffer;
}

int main()
{
    size_t sla_size;
    unsigned char *sla_bytes = readSlaFile("/mnt/c/Users/dzonerzy/AppData/Local/Programs/Python/Python311/Lib/site-packages/pypcode/processors/x86/data/languages/x86.sla", &sla_size);

    if (!sla_bytes)
    {
        printf("Failed to read SLEIGH file\n");
        return 1;
    }

    PcodeContext *ctx = pcode_context_create(sla_bytes, sla_size);
    const char *bytes = "\x55\x48\x8b\x05\xb8\x13\x00\x00"; // Example machine code
    unsigned int num_bytes = 8;
    uint64_t address = 0x1000;
    unsigned int max_instructions = 10;

    RegisterInfoListC *registers = pcode_context_get_all_registers(ctx);
    printf("Got %u registers\n", registers->count);
    for (unsigned int i = 0; i < registers->count; i++)
    {
        RegisterInfoC reg = registers->registers[i];
        printf("Register: %s, Space: %s, Offset: 0x%x, Size: %u\n", reg.name, reg.varnode.space->name, reg.varnode.offset, reg.varnode.size);
    }

    // Disassemble
    PcodeDisassemblyC *disassembly = pcode_disassemble(ctx, bytes, num_bytes, address, max_instructions);
    unsigned int instruction_count = disassembly->num_instructions;

    printf("Disassembled %u instructions:\n", instruction_count);
    for (unsigned int i = 0; i < instruction_count; i++)
    {
        DisassemblyInstructionC instruction = disassembly->instructions[i];
        printf("0x%lx: %s %s\n", instruction.address, instruction.mnemonic, instruction.body);
    }

    pcode_disassembly_free(disassembly);

    // Translate
    PcodeTranslationC *translation = pcode_translate(ctx, bytes, num_bytes, address, max_instructions, 0);
    unsigned int op_count = translation->num_ops;

    printf("Translated %u Pcode operations\n", op_count);
    for (unsigned int i = 0; i < op_count; i++)
    {
        PcodeOpC op = translation->ops[i];
        printf("Opcode: %u\n", op.opcode);
        if (op.output)
        {
            printf("Output: %s, Offset: 0x%x, Size: %u\n", op.output.space->name, op.output.offset, op.output.size);
        }
        printf("Inputs:\n");
        for (unsigned int j = 0; j < op.num_inputs; j++)
        {
            printf("\tSpace: %s, Offset: 0x%x, Size: %u\n", op.inputs[j].space->name, op.inputs[j].offset, op.inputs[j].size);
        }
    }

    pcode_translation_free(translation);
    pcode_context_free(ctx);

    return 0;
}