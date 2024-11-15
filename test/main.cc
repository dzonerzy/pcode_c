// main.c

#if _WINDOWS
#include <windows.h>
#endif
#include <stdio.h>
#include <pcode_wrapper.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>

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
    // if windows, use "..\\processors\\x86\\data\\languages\\x86.sla"
    // if linux, use "../processors/x86/data/languages/x86.sla"

#if _WINDOWS
    unsigned char *sla_bytes = readSlaFile("..\\processors\\x86\\data\\languages\\x86.sla", &sla_size);
#else
    unsigned char *sla_bytes = readSlaFile("../processors/x86/data/languages/x86.sla", &sla_size);
#endif

    if (!sla_bytes)
    {
        printf("Failed to read SLEIGH file\n");
        return 1;
    }

    PcodeContext *ctx = pcode_context_create(sla_bytes, sla_size);

    pcode_context_set_variable_default(ctx, "addrsize", 1);
    pcode_context_set_variable_default(ctx, "opsize", 1);

    const char *bytes = "\x55\x8b\xec\x83\xec\x08\x90\x90\xc9\xc3";
    unsigned int num_bytes = 10;
    uint64_t address = 0x1000;
    unsigned int max_instructions = 1024;

    // count how much time it takes to disassemble 100000 times

    // take the time before the loop
    auto start = clock();

    for (int i = 0; i < 100000; i++)
    {

        // Disassemble
        PcodeDisassemblyC *disassembly = pcode_disassemble(ctx, bytes, num_bytes, address, max_instructions);
        // printf("Disassembled %u instructions:\n", disassembly->num_instructions);
        /*for (unsigned int i = 0; i < disassembly->num_instructions; i++)
        {
            DisassemblyInstructionC *instruction = disassembly->instructions[i];
            printf("0x%llx: %s %s\n", instruction->address, instruction->mnemonic, instruction->body);
        }*/

        pcode_disassembly_free(disassembly);
        // pcode_mempool_clear();
    }

    // take the time after the loop
    auto end = clock();

    // calculate the time difference
    auto elapsed = (end - start) / (double)CLOCKS_PER_SEC;

    printf("Elapsed time: %f\n", elapsed);

    // Translate
    /*PcodeTranslationC *translation = pcode_translate(ctx, bytes, num_bytes, address, max_instructions, bb_terminating);
    unsigned int op_count = translation->num_ops;

    printf("Translated %u Pcode operations\n", op_count);
    for (unsigned int i = 0; i < op_count; i++)
    {
        PcodeOpC *op = translation->ops[i];
        printf("Opcode: %u\n", op->opcode);

        if (op->output)
        {
            printf("Output: %s, Offset: 0x%llx, Size: %u\n", op->output->space->name, op->output->offset, op->output->size);
        }

        printf("Inputs:\n");
        for (unsigned int j = 0; j < op->num_inputs; j++)
        {
            printf("\tSpace: %s, Offset: 0x%llx, Size: %u\n", op->inputs[j]->space->name, op->inputs[j]->offset, op->inputs[j]->size);
        }
    }

    pcode_translation_free(translation);*/

    auto start2 = clock();

    for (int i = 0; i < 100000; i++)
    {
        // Translate
        PcodeTranslationC *translation = pcode_translate(ctx, bytes, num_bytes, address, max_instructions, 0);

        pcode_translation_free(translation);
    }

    auto end2 = clock();

    auto elapsed2 = (end2 - start2) / (double)CLOCKS_PER_SEC;

    printf("Elapsed time: %f\n", elapsed2);

    pcode_mempool_clear();

    pcode_context_free(ctx);
    free(sla_bytes);

    return 0;
}