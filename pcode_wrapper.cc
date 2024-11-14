#include "pcode_wrapper.h"
#include "pcode_native.cc" // Include the existing implementation

#include <cstring>
#include <cstdlib>
#include <sstream>

namespace PcodeMemoryPools
{
    static MemoryPool<VarnodeDataC> varnodePool;
    static MemoryPool<PcodeOpC> pcodeOpPool;
}

std::vector<uint8_t> convertToVector(const unsigned char *data, size_t size)
{
    return {data, data + size};
}

// Utility function to convert AddrSpace to AddrSpaceC
AddrSpaceC *addrSpaceToC(AddrSpace *addr_space)
{
    AddrSpaceC *addr_space_c = (AddrSpaceC *)malloc(sizeof(AddrSpaceC));
    addr_space_c->name = strdup(addr_space->getName().c_str());
    addr_space_c->index = addr_space->getIndex();
    addr_space_c->address_size = addr_space->getAddrSize();
    addr_space_c->word_size = addr_space->getWordSize();
    addr_space_c->highest = addr_space->getHighest();
    addr_space_c->pointer_lower_bound = addr_space->getPointerLowerBound();
    addr_space_c->pointer_upper_bound = addr_space->getPointerUpperBound();

    if (addr_space->isBigEndian())
        addr_space_c->flags |= big_endian;
    if (addr_space->isHeritaged())
        addr_space_c->flags |= heritaged;
    if (addr_space->doesDeadcode())
        addr_space_c->flags |= does_deadcode;
    if (addr_space->isReverseJustified())
        addr_space_c->flags |= reverse_justification;
    if (addr_space->isFormalStackSpace())
        addr_space_c->flags |= formal_stackspace;
    if (addr_space->isOverlay())
        addr_space_c->flags |= overlay;
    if (addr_space->isOverlayBase())
        addr_space_c->flags |= overlaybase;
    if (addr_space->isTruncated())
        addr_space_c->flags |= truncated;
    if (addr_space->hasPhysical())
        addr_space_c->flags |= hasphysical;
    if (addr_space->isOtherSpace())
        addr_space_c->flags |= is_otherspace;
    if (addr_space->hasNearPointers())
        addr_space_c->flags |= has_nearpointers;

    addr_space_c->n_space = reinterpret_cast<NativeAddrSpace *>(addr_space);

    return addr_space_c;
}

// Utility function to convert VarnodeData to VarnodeDataC
void varnodeDataToC(VarnodeDataC *varnode_c, const VarnodeData &varnode)
{
    varnode_c->space = addrSpaceToC(varnode.space);
    varnode_c->offset = varnode.offset;
    varnode_c->size = varnode.size;
}

// Utility function to convert map<VarnodeData, string> to RegisterInfoListC
RegisterInfoListC *mapToRegisterInfoListC(const std::map<VarnodeData, std::string> &regmap)
{
    RegisterInfoListC *reg_list = (RegisterInfoListC *)malloc(sizeof(RegisterInfoListC));
    reg_list->count = regmap.size();
    reg_list->registers = (RegisterInfoC *)malloc(reg_list->count * sizeof(RegisterInfoC));

    uint32_t i = 0;
    for (const auto &pair : regmap)
    {
        varnodeDataToC(&reg_list->registers[i].varnode, pair.first);
        reg_list->registers[i].name = strdup(pair.second.c_str());
        i++;
    }

    return reg_list;
}

extern "C"
{
    PcodeContext *pcode_context_create(unsigned char *slaBytes, size_t slaSize)
    {
        return reinterpret_cast<PcodeContext *>(new Context(convertToVector(slaBytes, slaSize)));
    }

    void pcode_context_free(PcodeContext *ctx)
    {
        delete reinterpret_cast<Context *>(ctx);
    }

    void pcode_context_set_variable_default(PcodeContext *ctx, const char *nm, uint32_t val)
    {
        Context *context = reinterpret_cast<Context *>(ctx);
        std::string name(nm);
        context->m_context_db.setVariableDefault(name, val);
    }

    RegisterInfoListC *pcode_context_get_all_registers(PcodeContext *ctx)
    {
        Context *context = reinterpret_cast<Context *>(ctx);
        std::map<VarnodeData, std::string> regmap;
        context->m_sleigh->getAllRegisters(regmap);
        return mapToRegisterInfoListC(regmap);
    }

    const char *pcode_context_get_register_name(PcodeContext *ctx, NativeAddrSpace *space, unsigned long long offset, int32_t size)
    {
        Context *context = reinterpret_cast<Context *>(ctx);
        return strdup(context->m_sleigh->getRegisterName(reinterpret_cast<AddrSpace *>(space), offset, size).c_str());
    }

    PcodeDisassemblyC *pcode_disassemble(PcodeContext *ctx, const char *bytes, unsigned int num_bytes, unsigned long long address, unsigned int max_instructions)
    {
        Context *context = reinterpret_cast<Context *>(ctx);
        std::unique_ptr<Disassembly> disassembly;

        try
        {
            disassembly = context->disassemble(bytes, num_bytes, address, max_instructions);
        }
        catch (const ghidra::LowlevelError &e)
        {
            return NULL;
        }

        PcodeDisassemblyC *result = (PcodeDisassemblyC *)malloc(sizeof(PcodeDisassemblyC));
        result->num_instructions = disassembly->m_instructions.size();
        result->instructions = (DisassemblyInstructionC *)malloc(result->num_instructions * sizeof(DisassemblyInstructionC));

        for (uint32_t i = 0; i < result->num_instructions; ++i)
        {
            DisassemblyInstruction &ins = disassembly->m_instructions[i];
            DisassemblyInstructionC &ins_c = result->instructions[i];

            ins_c.address = ins.m_addr.getOffset();
            ins_c.length = ins.m_length;
            ins_c.mnemonic = strdup(ins.m_mnem.c_str());
            ins_c.body = strdup(ins.m_body.c_str());
        }

        return result;
    }

    void pcode_disassembly_free(PcodeDisassemblyC *disas)
    {
        for (uint32_t i = 0; i < disas->num_instructions; ++i)
        {
            DisassemblyInstructionC &ins_c = disas->instructions[i];
            free((void *)ins_c.mnemonic);
            free((void *)ins_c.body);
        }
        free(disas->instructions);
        free(disas);
    }

    PcodeTranslationC *pcode_translate(PcodeContext *ctx, const char *bytes, unsigned int num_bytes, unsigned long long base_address, unsigned int max_instructions, uint32_t flags)
    {
        Context *context = reinterpret_cast<Context *>(ctx);
        std::unique_ptr<Translation> translation = nullptr;

        try
        {
            translation = context->translate(bytes, num_bytes, base_address, max_instructions, flags);
        }
        catch (const ghidra::LowlevelError &e)
        {
            return NULL;
        }

        PcodeTranslationC *result = (PcodeTranslationC *)malloc(sizeof(PcodeTranslationC));
        result->num_ops = translation->m_ops.size();
        result->ops = (PcodeOpC *)malloc(result->num_ops * sizeof(PcodeOpC));

        for (uint32_t i = 0; i < result->num_ops; ++i)
        {
            PcodeOp &op = translation->m_ops[i];
            PcodeOpC &op_c = result->ops[i];

            op_c.opcode = op.m_opcode;

            if (op.m_output)
            {
                op_c.output = (VarnodeDataC *)malloc(sizeof(VarnodeDataC));
                varnodeDataToC(op_c.output, *op.m_output);
            }
            else
            {
                op_c.output = NULL;
            }

            op_c.num_inputs = op.m_inputs.size();
            op_c.inputs = (VarnodeDataC *)malloc(op_c.num_inputs * sizeof(VarnodeDataC));
            for (uint32_t j = 0; j < op_c.num_inputs; ++j)
            {
                varnodeDataToC(&op_c.inputs[j], op.m_inputs[j]);
            }
        }
        return result;
    }

    void pcode_translation_free(PcodeTranslationC *trans)
    {
        for (uint32_t i = 0; i < trans->num_ops; ++i)
        {
            PcodeOpC &op_c = trans->ops[i];
            if (op_c.output)
            {
                free((void *)op_c.output->space->name);
                free(op_c.output->space);
                free(op_c.output);
            }
            for (uint32_t j = 0; j < op_c.num_inputs; ++j)
            {
                free((void *)op_c.inputs[j].space->name);
                free(op_c.inputs[j].space);
            }
            free(op_c.inputs);
        }
        free(trans->ops);
        free(trans);
    }

    const char *pcode_varcode_get_register_name(NativeAddrSpace *space, unsigned long long offset, int32_t size)
    {
        ghidra::AddrSpace *addr_space = reinterpret_cast<ghidra::AddrSpace *>(space);
        return strdup(addr_space->getTrans()->getRegisterName(addr_space, offset, size).c_str());
    }

    AddrSpaceC *pcode_varnode_get_space_from_const(unsigned long long offset)
    {
        ghidra::AddrSpace *space = (AddrSpace *)(uintp)offset;
        return addrSpaceToC(space);
    }

} // extern "C"
