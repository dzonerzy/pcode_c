#include "pcode_wrapper.h"
#include "pcode_native.cc" // Include the existing implementation

#include <cstring>
#include <cstdlib>
#include <sstream>
#include <optional>

struct PcodeOpCKey
{
    ghidra::OpCode opcode;
    VarnodeData *output;
    std::vector<VarnodeData> inputs;

    bool operator==(const PcodeOpCKey &other) const
    {
        if (opcode != other.opcode || inputs.size() != other.inputs.size())
        {
            return false;
        }

        // Compare output's address space name, offset, and size
        if (output && other.output)
        {
            std::string name1 = output->space ? output->space->getName() : "";
            std::string name2 = other.output->space ? other.output->space->getName() : "";

            if (std::strcmp(name1.c_str(), name2.c_str()) != 0 ||
                output->offset != other.output->offset ||
                output->size != other.output->size)
            {
                return false;
            }
        }
        else if (output || other.output) // One is null, the other is not
        {
            return false;
        }

        // Compare inputs' address space names, offsets, and sizes
        for (size_t i = 0; i < inputs.size(); ++i)
        {
            std::string name1 = inputs[i].space ? inputs[i].space->getName() : "";
            std::string name2 = other.inputs[i].space ? other.inputs[i].space->getName() : "";

            if (std::strcmp(name1.c_str(), name2.c_str()) != 0 ||
                inputs[i].offset != other.inputs[i].offset ||
                inputs[i].size != other.inputs[i].size)
            {
                return false;
            }
        }

        return true;
    }
};

struct VarnodeDataCKey
{
    AddrSpace *space;
    uint64_t offset;
    uint32_t size;

    bool operator==(const VarnodeDataCKey &other) const
    {
        // Compare address space names
        const char *name1 = space ? space->getName().c_str() : nullptr;
        const char *name2 = other.space ? other.space->getName().c_str() : nullptr;

        if ((name1 && name2 && std::strcmp(name1, name2) != 0) || (!name1 && name2) || (name1 && !name2))
        {
            return false;
        }

        // Compare offset and size
        return offset == other.offset && size == other.size;
    }
};

struct AddrSpaceCKey
{
    AddrSpace *space;

    bool operator==(const AddrSpaceCKey &other) const
    {
        // Compare name
        if (space->getName() != other.space->getName())
        {
            return false;
        }

        // Compare other fields
        return space->getIndex() == other.space->getIndex() &&
               space->getAddrSize() == other.space->getAddrSize() &&
               space->getWordSize() == other.space->getWordSize() &&
               space->getHighest() == other.space->getHighest() &&
               space->getPointerLowerBound() == other.space->getPointerLowerBound() &&
               space->getPointerUpperBound() == other.space->getPointerUpperBound();
    }
};

struct DisassemblyInstructionCKey
{
    DisassemblyInstruction instruction;

    bool operator==(const DisassemblyInstructionCKey &other) const
    {
        if (instruction.m_addr != other.instruction.m_addr || instruction.m_length != other.instruction.m_length)
        {
            return false;
        }

        // Compare mnemonic and body
        return instruction.m_mnem == other.instruction.m_mnem && instruction.m_body == other.instruction.m_body;
    }
};

// Hash specialization for PcodeOpCKey
namespace std
{
    template <>
    struct hash<PcodeOpCKey>
    {
        size_t operator()(const PcodeOpCKey &key) const
        {
            // Hash the opcode
            size_t hashValue = std::hash<uint32_t>()(key.opcode);

            // Hash the output's address space name, if it exists
            if (key.output && key.output->space)
            {
                hashValue ^= (std::hash<std::string>()(key.output->space->getName()) ^ std::hash<uint64_t>()(key.output->offset) ^ std::hash<int32_t>()(key.output->size));
            }

            // Hash each input's address space name
            for (auto input : key.inputs)
            {
                if (input.space)
                {
                    hashValue ^= (std::hash<std::string>()(input.space->getName()) ^ std::hash<uint64_t>()(input.offset) ^ std::hash<int32_t>()(input.size));
                }
            }

            return hashValue;
        }
    };

    template <>
    struct hash<VarnodeDataCKey>
    {
        size_t operator()(const VarnodeDataCKey &key) const
        {
            size_t hashValue = 0;

            // Hash address space name
            if (key.space)
            {
                hashValue ^= std::hash<std::string>()(key.space->getName()) << 1;
            }

            // Hash offset and size
            hashValue ^= std::hash<uint64_t>()(key.offset) << 2;
            hashValue ^= std::hash<int32_t>()(key.size) << 3;

            return hashValue;
        }
    };

    template <>
    struct hash<AddrSpaceCKey>
    {
        size_t operator()(const AddrSpaceCKey &key) const
        {
            size_t hashValue = 0;

            // Hash the name
            hashValue ^= std::hash<std::string>()(key.space->getName()) << 1;

            // Combine with other fields
            hashValue ^= std::hash<uint32_t>()(key.space->getIndex()) << 2;
            hashValue ^= std::hash<uint32_t>()(key.space->getAddrSize()) << 3;
            hashValue ^= std::hash<uint32_t>()(key.space->getWordSize()) << 4;
            hashValue ^= std::hash<uint64_t>()(key.space->getHighest()) << 5;
            hashValue ^= std::hash<uint64_t>()(key.space->getPointerLowerBound()) << 6;
            hashValue ^= std::hash<uint64_t>()(key.space->getPointerUpperBound()) << 7;

            return hashValue;
        }
    };

    template <>
    struct hash<DisassemblyInstructionCKey>
    {
        size_t operator()(const DisassemblyInstructionCKey &key) const
        {
            size_t hashValue = 0;

            // Hash address and length
            hashValue ^= std::hash<uint64_t>()(key.instruction.m_addr.getOffset()) << 1;
            hashValue ^= std::hash<uint64_t>()(key.instruction.m_length) << 2;

            // Hash mnemonic and body
            hashValue ^= std::hash<std::string>()(key.instruction.m_mnem) << 3;
            hashValue ^= std::hash<std::string>()(key.instruction.m_body) << 4;

            return hashValue;
        }
    };
}
namespace PcodeMemoryPools
{
    static MemoryPool<VarnodeDataC, VarnodeDataCKey> varnodePool;
    static MemoryPool<PcodeOpC, PcodeOpCKey> pcodeOpPool;
    static MemoryPool<AddrSpaceC, AddrSpaceCKey> addrSpacePool;
    static MemoryPool<DisassemblyInstructionC, DisassemblyInstructionCKey> disassemblyInstructionPool;
}

// Utility function to convert AddrSpace to AddrSpaceC
inline AddrSpaceC *addrSpaceToC(AddrSpace *addr_space)
{
    AddrSpaceC *addr_space_c = PcodeMemoryPools::addrSpacePool.acquireWithKey(AddrSpaceCKey{addr_space});

    // Allocate or reuse the `name` string
    if (addr_space_c->name)
    {
        free((void *)addr_space_c->name); // Free the old name to avoid leaks
    }
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

        std::vector<DisassemblyInstructionCKey> keys;
        keys.reserve(result->num_instructions);

        for (uint32_t i = 0; i < result->num_instructions; ++i)
        {
            const DisassemblyInstruction &ins = disassembly->m_instructions[i];
            keys.emplace_back(DisassemblyInstructionCKey{ins});
        }

        result->instructions = PcodeMemoryPools::disassemblyInstructionPool.batchAcquire(result->num_instructions, keys); // Acquire a batch of DisassemblyInstructionC pointers

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
            ins_c->body = ins_c->bodyHolder.get();                               // Set raw pointer for Go access

            ins_c->address = ins.m_addr.getOffset();
            ins_c->length = ins.m_length;
        }

        return result;
    }

    void pcode_disassembly_free(PcodeDisassemblyC *disas)
    {
        // Return the array of instruction pointers to the memory pool
        PcodeMemoryPools::disassemblyInstructionPool.batchRelease(disas->instructions, disas->num_instructions);
        // Free the disassembly result structure itself (not managed by the pool)
        free(disas);
    }

    PcodeTranslationC *pcode_translate(PcodeContext *ctx, const char *bytes, unsigned int num_bytes, unsigned long long base_address, unsigned int max_instructions, uint32_t flags)
    {
        Context *context = reinterpret_cast<Context *>(ctx);
        auto translationOpt = translateSafe(reinterpret_cast<Context *>(ctx), bytes, num_bytes, base_address, max_instructions, flags);

        // Check if translation was successful
        if (!translationOpt.has_value())
        {
            return nullptr; // Handle error by returning null if translation failed
        }

        // Access the successful translation from the optional
        std::unique_ptr<Translation> &translation = translationOpt.value();

        // Allocate the result structure
        PcodeTranslationC *result = (PcodeTranslationC *)malloc(sizeof(PcodeTranslationC));
        result->num_ops = translation->m_ops.size();
        // generate keys for batchAcquire
        std::vector<PcodeOpCKey> keys;
        keys.reserve(result->num_ops);

        for (uint32_t i = 0; i < result->num_ops; ++i)
        {
            PcodeOp &op = translation->m_ops[i];
            keys.emplace_back(PcodeOpCKey{op.m_opcode, op.m_output ? &op.m_output.value() : nullptr, op.m_inputs});
        }

        result->ops = PcodeMemoryPools::pcodeOpPool.batchAcquire(result->num_ops); // Acquire a batch of PcodeOpC pointers

        for (uint32_t i = 0; i < result->num_ops; ++i)
        {
            PcodeOp &op = translation->m_ops[i];
            PcodeOpC *op_c = result->ops[i];
            op_c->opcode = op.m_opcode;

            // Handle output varnode, if it exists
            if (op.m_output)
            {
                op_c->output = PcodeMemoryPools::varnodePool.acquireWithKey(VarnodeDataCKey{op.m_output->space, op.m_output->offset, op.m_output->size});
                varnodeDataToC(op_c->output, *op.m_output);
            }
            else
            {
                op_c->output = nullptr;
            }

            // Handle input varnodes
            op_c->num_inputs = op.m_inputs.size();
            // op_c->inputs = new VarnodeDataC *[op_c->num_inputs]; // Allocate array of pointers to VarnodeDataC
            // use batchAcquire
            // generate keys for batchAcquire
            std::vector<VarnodeDataCKey> keys;

            keys.reserve(op_c->num_inputs);
            for (uint32_t j = 0; j < op_c->num_inputs; ++j)
            {
                keys.emplace_back(VarnodeDataCKey{op.m_inputs[j].space, op.m_inputs[j].offset, op.m_inputs[j].size});
            }

            op_c->inputs = PcodeMemoryPools::varnodePool.batchAcquire(op_c->num_inputs, keys); // Acquire a batch of VarnodeDataC pointers

            for (uint32_t j = 0; j < op_c->num_inputs; ++j)
            {

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
                free((void *)op_c->output->space->name); // Free the name string
                op_c->output->space->name = nullptr;
                PcodeMemoryPools::addrSpacePool.release(op_c->output->space);
                PcodeMemoryPools::varnodePool.release(op_c->output);
            }

            // Release each input varnode
            if (op_c->inputs)
            {
                for (uint32_t j = 0; j < op_c->num_inputs; ++j)
                {
                    free((void *)op_c->inputs[j]->space->name); // Free the name string
                    op_c->inputs[j]->space->name = nullptr;
                    PcodeMemoryPools::addrSpacePool.release(op_c->inputs[j]->space);
                }

                PcodeMemoryPools::varnodePool.batchRelease(op_c->inputs, op_c->num_inputs); // Use batchRelease for input varnodes
            }
        }

        PcodeMemoryPools::pcodeOpPool.batchRelease(trans->ops, trans->num_ops); // Return PcodeOpC objects to the pool in a batch

        free(trans); // Free the translation struct (not managed by the pool)
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

    void pcode_mempool_clear()
    {
        PcodeMemoryPools::varnodePool.clear();
        PcodeMemoryPools::pcodeOpPool.clear();
        PcodeMemoryPools::addrSpacePool.clear();
        PcodeMemoryPools::disassemblyInstructionPool.clear();
    }

} // extern "C"
