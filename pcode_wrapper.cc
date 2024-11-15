#include "pcode_wrapper.h"
#include "pcode_native.cc" // Include the existing implementation

#include <cstring>
#include <cstdlib>
#include <sstream>
#include <optional>

namespace PcodeMemoryPools
{
    static MemoryPool<VarnodeDataC> varnodePool;
    static MemoryPool<PcodeOpC> pcodeOpPool;
    static MemoryPool<AddrSpaceC> addrSpacePool;
    static MemoryPool<DisassemblyInstructionC> disassemblyInstructionPool;
}

// Utility function to convert AddrSpace to AddrSpaceC
inline AddrSpaceC *addrSpaceToC(AddrSpace *addr_space)
{
    AddrSpaceC *addr_space_c = PcodeMemoryPools::addrSpacePool.acquire();
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

std::optional<std::unique_ptr<Translation>> translateSafe(Context *context, const char *bytes, unsigned int num_bytes, uint64_t base_address, unsigned int max_instructions, uint32_t flags)
{
    try
    {
        return context->translate(bytes, num_bytes, base_address, max_instructions, flags);
    }
    catch (const ghidra::LowlevelError &)
    {
        return std::nullopt; // Return nullopt instead of throwing
    }
}

std::optional<std::unique_ptr<Disassembly>> disassembleSafe(Context *context, const char *bytes, unsigned int num_bytes, uint64_t address, unsigned int max_instructions)
{
    try
    {
        return context->disassemble(bytes, num_bytes, address, max_instructions);
    }
    catch (const ghidra::LowlevelError &)
    {
        return std::nullopt; // Return nullopt on error
    }
}

extern "C"
{
    PcodeContext *pcode_context_create(unsigned char *slaBytes, size_t slaSize)
    {
        Span<const uint8_t> slaSpan(slaBytes, slaSize); // Create a Span directly from pointer and size
        return reinterpret_cast<PcodeContext *>(new Context(slaSpan));
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

        // Call disassembleSafe to attempt disassembly
        auto disassemblyOpt = disassembleSafe(context, bytes, num_bytes, address, max_instructions);

        // Check if disassembly was successful
        if (!disassemblyOpt.has_value())
        {
            return nullptr; // Handle error by returning null if disassembly failed
        }

        // Access the successful disassembly from the optional
        std::unique_ptr<Disassembly> &disassembly = disassemblyOpt.value();

        PcodeDisassemblyC *result = (PcodeDisassemblyC *)malloc(sizeof(PcodeDisassemblyC));
        result->num_instructions = disassembly->m_instructions.size();
        result->instructions = PcodeMemoryPools::disassemblyInstructionPool.batchAcquire(result->num_instructions); // Acquire a batch of DisassemblyInstructionC pointers

        for (uint32_t i = 0; i < result->num_instructions; ++i)
        {
            DisassemblyInstruction &ins = disassembly->m_instructions[i];
            DisassemblyInstructionC *ins_c = result->instructions[i];

            // Allocate storage for mnemonic with null-termination
            auto mnemonicHolder = std::shared_ptr<char>(new char[ins.m_mnem.size() + 1], std::default_delete<char[]>());
            std::copy(ins.m_mnem.c_str(), ins.m_mnem.c_str() + ins.m_mnem.size() + 1, mnemonicHolder.get());
            ins_c->mnemonicHolder = std::const_pointer_cast<const char>(mnemonicHolder); // Convert to const char* shared_ptr
            ins_c->mnemonic = ins_c->mnemonicHolder.get();                               // Set raw pointer for Go access

            // Allocate storage for body with null-termination
            auto bodyHolder = std::shared_ptr<char>(new char[ins.m_body.size() + 1], std::default_delete<char[]>());
            std::copy(ins.m_body.c_str(), ins.m_body.c_str() + ins.m_body.size() + 1, bodyHolder.get());
            ins_c->bodyHolder = std::const_pointer_cast<const char>(bodyHolder); // Convert to const char* shared_ptr
            ins_c->body = ins_c->bodyHolder.get();                               // Set raw pointer for Go access                                                          // Set raw pointer for Go access
        }

        return result;
    }

    void pcode_disassembly_free(PcodeDisassemblyC *disas)
    {
        for (uint32_t i = 0; i < disas->num_instructions; ++i)
        {
            DisassemblyInstructionC *ins_c = disas->instructions[i];
            free((void *)ins_c->mnemonic);
            free((void *)ins_c->body);
        }
        free(disas->instructions);
        free(disas);
    }

    PcodeTranslationC *pcode_translate(PcodeContext *ctx, const char *bytes, unsigned int num_bytes, unsigned long long base_address, unsigned int max_instructions, uint32_t flags)
    {
        Context *context = reinterpret_cast<Context *>(ctx);
        std::unique_ptr<Translation> translation = nullptr;

        auto translationOpt = translateSafe(reinterpret_cast<Context *>(ctx), bytes, num_bytes, base_address, max_instructions, flags);

        // Check if translation was successful
        if (!translationOpt.has_value())
        {
            return nullptr; // Handle error by returning null if translation failed
        }

        // Access the successful translation from the optional
        std::unique_ptr<Translation> &translation = translationOpt.value();

        // Allocate the result structure
        PcodeTranslationC *result = new PcodeTranslationC;
        result->num_ops = translation->m_ops.size();
        result->ops = PcodeMemoryPools::pcodeOpPool.batchAcquire(result->num_ops); // Acquire a batch of PcodeOpC pointers

        for (uint32_t i = 0; i < result->num_ops; ++i)
        {
            PcodeOp &op = translation->m_ops[i];
            PcodeOpC *op_c = result->ops[i];
            op_c->opcode = op.m_opcode;

            // Handle output varnode, if it exists
            if (op.m_output)
            {
                op_c->output = PcodeMemoryPools::varnodePool.acquire();
                varnodeDataToC(op_c->output, *op.m_output);
            }
            else
            {
                op_c->output = nullptr;
            }

            // Handle input varnodes
            op_c->num_inputs = op.m_inputs.size();
            op_c->inputs = new VarnodeDataC *[op_c->num_inputs]; // Allocate array of pointers to VarnodeDataC
            for (uint32_t j = 0; j < op_c->num_inputs; ++j)
            {
                op_c->inputs[j] = PcodeMemoryPools::varnodePool.acquire();
                varnodeDataToC(op_c->inputs[j], op.m_inputs[j]);
            }
        }
        return result;
    }

    void pcode_translation_free(PcodeTranslationC *trans)
    {
        for (uint32_t i = 0; i < trans->num_ops; ++i)
        {
            PcodeOpC *op_c = trans->ops[i];

            // Release the output varnode, if it exists
            if (op_c->output)
            {
                PcodeMemoryPools::varnodePool.release(op_c->output);
            }

            // Release each input varnode
            for (uint32_t j = 0; j < op_c->num_inputs; ++j)
            {
                PcodeMemoryPools::varnodePool.release(op_c->inputs[j]);
            }
            delete[] op_c->inputs; // Delete the array of input pointers
        }

        PcodeMemoryPools::pcodeOpPool.batchRelease(trans->ops, trans->num_ops); // Return PcodeOpC objects to the pool in a batch
        delete trans;                                                           // Delete the translation struct
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
