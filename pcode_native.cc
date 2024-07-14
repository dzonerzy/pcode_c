#include <cstdio>
#include <optional>
#include <string>
#include <unordered_set>
#include <memory>

#include "sleigh/error.hh"
#include "sleigh/loadimage.hh"
#include "sleigh/opcodes.hh"
#include "sleigh/sleigh.hh"
#include "sleigh/space.hh"
#include "sleigh/translate.hh"
#include "sleigh/xml.hh"

using namespace ghidra;

// #define DEBUG 1

#ifndef DEBUG
#define DEBUG 0
#endif

#if DEBUG
#define LOG(fmt, ...) fprintf(stderr, "pcode_native: " fmt "\n", ##__VA_ARGS__);
#else
#define LOG(fmt, ...)
#endif

#define MIN(x, y) ((x) < (y) ? (x) : (y))

struct PcodeOp
{
    OpCode m_opcode;
    std::optional<VarnodeData> m_output;
    std::vector<VarnodeData> m_inputs;
};

class ContextPypcode : public ContextInternal
{
    bool m_finalized;
    std::unordered_set<string> m_variables;

public:
    ContextPypcode() : ContextInternal()
    {
        m_finalized = false;
    }

    void finalize()
    {
        m_finalized = true;
    }

    virtual void registerVariable(const string &nm, int4 sbit, int4 ebit)
    {
        if (!m_finalized)
        {
            ContextInternal::registerVariable(nm, sbit, ebit);
            m_variables.insert(nm);
        }
    }

    void resetAllVariables()
    {
        for (const string &nm : m_variables)
        {
            auto val = ContextDatabase::getDefaultValue(nm);
            setVariableRegion(nm, Address(Address::m_minimal), Address(), val);
        }
    }
};

class SimpleLoadImage : public LoadImage
{
    uintb m_baseaddr;
    int4 m_length;
    const unsigned char *m_data;

public:
    SimpleLoadImage() : LoadImage("nofile")
    {
        m_baseaddr = 0;
        m_data = NULL;
        m_length = 0;
    }

    void setData(uintb ad, const unsigned char *ptr, int4 sz)
    {
        m_baseaddr = ad;
        m_data = ptr;
        m_length = sz;
    }

    void loadFill(uint1 *ptr, int4 size, const Address &addr)
    {
        LOG("Filling %d bytes at %lx", size, addr.getOffset());
        uintb start = addr.getOffset();
        uintb max = m_baseaddr + m_length - 1;

        //
        // When decoding an instruction, SLEIGH will attempt to pull in several
        // bytes at a time, starting at each instruction boundary.
        //
        // If the start address is outside of the defined range, bail out.
        // Otherwise, if we have some data to provide but cannot satisfy the
        // entire request, fill the remainder of the buffer with zero.
        //
        if (start > max || start < m_baseaddr)
        {
            throw std::out_of_range("Attempting to lift outside buffer range");
        }

        for (int4 i = 0; i < size; i++)
        {
            uintb curoff = start + i;
            if ((curoff < m_baseaddr) || (curoff > max))
            {
                ptr[i] = 0;
                continue;
            }
            uintb diff = curoff - m_baseaddr;
            ptr[i] = m_data[(int4)diff];
        }
    }

    virtual string getArchType(void) const
    {
        return "myload";
    }
    virtual void adjustVma(long adjust)
    {
    }
};

class PcodeEmitCacher : public PcodeEmit
{
public:
    std::vector<PcodeOp> m_ops;
    bool m_bb_terminating_op_emitted;

    PcodeEmitCacher() : m_bb_terminating_op_emitted(false)
    {
        m_ops.reserve(512);
    }

    // Encode P-code ops into csleigh structures and append them to the translation buffer
    void dump(const Address &addr, OpCode opc, VarnodeData *outvar, VarnodeData *invars, int4 num_invars)
    {
        LOG("Emitting pcode op %d with %d-in,%d-out varnodes from %lx",
            opc,
            num_invars,
            outvar ? 1 : 0,
            addr.getOffset());
        m_bb_terminating_op_emitted |= opc == CPUI_BRANCH || opc == CPUI_CBRANCH || opc == CPUI_BRANCHIND ||
                                       opc == CPUI_RETURN || opc == CPUI_CALL || opc == CPUI_CALLIND;

        m_ops.emplace_back();
        PcodeOp &op = m_ops.back();

        op.m_opcode = opc;
        if (outvar)
        {
            op.m_output.emplace(*outvar);
        }
        op.m_inputs.reserve(num_invars);
        for (int i = 0; i < num_invars; i++)
        {
            op.m_inputs.emplace_back(invars[i]);
        }
    }
};

struct DisassemblyInstruction
{
    Address m_addr;
    uint64_t m_length;
    std::string m_mnem;
    std::string m_body;
};

class AssemblyEmitCacher : public AssemblyEmit
{
public:
    DisassemblyInstruction &m_disas;

    AssemblyEmitCacher(DisassemblyInstruction &disas) : m_disas(disas)
    {
    }

    void dump(const Address &addr, const std::string &mnem, const std::string &body)
    {
        m_disas.m_addr = addr;
        m_disas.m_mnem = mnem;
        m_disas.m_body = body;
    };
};

class Disassembly
{
public:
    std::vector<DisassemblyInstruction> m_instructions;

    Disassembly()
    {
        LOG("Disassembly %p created", this);
    }

    Disassembly(Disassembly &&o) noexcept : m_instructions(std::move(o.m_instructions))
    {
        LOG("Disassembly moved from %p to %p", &o, this);
    }

    ~Disassembly()
    {
        LOG("Disassembly %p released", this);
    }
};

class Translation
{
public:
    std::vector<PcodeOp> m_ops;

    Translation()
    {
        LOG("Translation %p created", this);
    }

    Translation(Translation &&o) noexcept : m_ops(std::move(o.m_ops))
    {
        LOG("Translation moved from %p to %p", &o, this);
    }

    ~Translation()
    {
        LOG("Translation %p released", this);
    }
};

enum TranslateFlags
{
    BB_TERMINATING = 1,
};

class Context
{
public:
    SimpleLoadImage m_loader;
    ContextPypcode m_context_db;
    DocumentStorage m_document_storage;
    Document *m_document;
    Element *m_tags;
    std::unique_ptr<Sleigh> m_sleigh;
    std::vector<Byte> m_slaBytes;

    Context(const std::vector<Byte> &slaBytes)
    {
        LOG("Context %p created", this);

        // FIXME: Globals...
        AttributeId::initialize();
        ElementId::initialize();

        m_slaBytes = slaBytes;

        LOG("Setting up translator");
        m_sleigh.reset(new Sleigh(&m_loader, &m_context_db));
        m_sleigh->initialize(m_slaBytes);
        m_context_db.finalize();
    }

    ~Context()
    {
        LOG("Context %p released", this);
    }

    void reset(void)
    {
        m_sleigh.reset(new Sleigh(&m_loader, &m_context_db));
        m_sleigh->initialize(m_slaBytes);
        m_context_db.finalize();
    }

    std::unique_ptr<Disassembly>
    disassemble(const char *bytes, unsigned int num_bytes, uint64_t address, unsigned int max_instructions)
    {
        LOG("%p Disassembling bytes=%p, num_bytes=%d, address=%lx", this, bytes, num_bytes, address);
        std::unique_ptr<Disassembly> disassembly(new Disassembly());
        int num_instructions = 0;
        uint32_t offset = 0;

        m_sleigh->fastReset();
        m_loader.setData(address, (const unsigned char *)bytes, num_bytes);
        disassembly->m_instructions.reserve(10);

        while ((offset < num_bytes) && (!max_instructions || (num_instructions < max_instructions)))
        {
            Address addr(m_sleigh->getDefaultCodeSpace(), address + offset);

            disassembly->m_instructions.emplace_back();
            DisassemblyInstruction &ins = disassembly->m_instructions.back();

            AssemblyEmitCacher asm_cache(ins);

            // Disassemble the next instruction. If an error occurs after successful disassembly of at least one
            // instruction, suppress the error and return the successful disassembly. If the caller attempts
            // disassembly again at the position where the error occurred, then propagate the error.
            try
            {
                ins.m_length = m_sleigh->printAssembly(asm_cache, addr);
            }
            catch (BadDataError &err)
            {
                if (offset)
                {
                    disassembly->m_instructions.resize(num_instructions);
                    break;
                }
                throw err;
            }

            num_instructions += 1;
            offset += ins.m_length;
        }

        return disassembly;
    }

    std::unique_ptr<Translation> translate(const char *bytes,
                                           unsigned int num_bytes,
                                           uint64_t base_address,
                                           unsigned int max_instructions,
                                           uint32_t flags)
    {
        LOG("%p Translating bytes=%p, num_bytes=%d, base_address=0x%lx, max_instructions=%d flags=0x%x",
            this,
            bytes,
            num_bytes,
            base_address,
            max_instructions,
            flags);
        std::unique_ptr<Translation> translation(new Translation);
        PcodeEmitCacher pcode_cache;
        uint32_t offset = 0;

        m_sleigh->fastReset();
        m_loader.setData(base_address, (const unsigned char *)bytes, num_bytes);

        int num_instructions = 0;
        while ((offset < num_bytes) && (!max_instructions || (num_instructions < max_instructions)))
        {
            Address addr(m_sleigh->getDefaultCodeSpace(), base_address + offset);
            LOG("Lifting at 0x%lx+0x%x=0x%lx", base_address, offset, base_address + offset);

            int imark_idx = pcode_cache.m_ops.size();
            pcode_cache.m_ops.emplace_back();

            // Translate the next instruction. If an error occurs after successful translation of at least one
            // instruction, suppress the error and return the successful translation. If the caller attempts
            // translation again at the position where the error occurred, then propagate the error.
            uint32_t num_bytes_decoded = 0;
            try
            {
                num_bytes_decoded = m_sleigh->oneInstruction(pcode_cache, addr);
            }
            catch (BadDataError &err)
            {
                if (offset)
                {
                    pcode_cache.m_ops.resize(imark_idx);
                    break;
                }
                throw err;
            }
            catch (UnimplError &err)
            {
                if (offset)
                {
                    pcode_cache.m_ops.resize(imark_idx);
                    break;
                }
                throw err;
            }

            PcodeOp &imark_op = pcode_cache.m_ops[imark_idx];
            imark_op.m_opcode = OpCode::CPUI_IMARK;

            // Add varnode to imark op for every decoded instruction in this translation
            for (int sum = 0; sum < num_bytes_decoded;)
            {
                imark_op.m_inputs.emplace_back();
                VarnodeData &imark_vn = imark_op.m_inputs.back();
                imark_vn.space = addr.getSpace();
                imark_vn.offset = addr.getOffset() + sum;
                imark_vn.size = m_sleigh->instructionLength(addr);

                sum += imark_vn.size;
                num_instructions++;
            }

            if ((flags & TranslateFlags::BB_TERMINATING) && pcode_cache.m_bb_terminating_op_emitted)
            {
                LOG("Reached end of block");
                break;
            }

            offset += num_bytes_decoded;
        }

        translation->m_ops = std::move(pcode_cache.m_ops);
        return translation;
    }
};
