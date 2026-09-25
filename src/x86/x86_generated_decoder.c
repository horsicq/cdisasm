#include "x86_generated_decoder.h"

#if USE_EXTRA_OPCODES

#include "generated/cdisasm_x86_isa_decode.inc"

#include <limits.h>
#include <string.h>

typedef struct x86_gen_state {
    const uint8_t *code;
    size_t code_size;
    size_t position;
    size_t opcode_end;
    cdisasm_mode mode;
    unsigned int operand_bits;
    unsigned int address_bits;
    uint32_t prefix_flags;
    uint8_t values[26];
    uint8_t rex;
    uint8_t rex_x;
    uint8_t rex_x4;
    uint8_t rex_present;
    uint8_t rex2_present;
    uint8_t segment_prefix;
    uint8_t evex_u_raw;
    uint8_t operand_override;
    uint8_t address_override;
    uint8_t repeat_prefix;
    uint8_t lock_prefix;
    uint8_t space;
    uint8_t map;
    uint8_t opcode;
    uint8_t modrm_parsed;
    uint8_t modrm_status;
    uint8_t mod;
    uint8_t reg;
    uint8_t rm;
    size_t modrm_end;
    cdisasm_x86_encoding encoding;
} x86_gen_state;

typedef struct x86_gen_candidate {
    const cdisasm_x86_gen_descriptor *descriptor;
    cdisasm_x86_encoding encoding;
    size_t length;
    int64_t relative_displacement;
    uint8_t has_relative;
    unsigned int score;
} x86_gen_candidate;

static cdisasm_status x86_gen_require(
    const x86_gen_state *state, size_t position, size_t count)
{
    if (position > CDISASM_MAX_INSTRUCTION_SIZE
        || count > CDISASM_MAX_INSTRUCTION_SIZE - position) {
        return CDISASM_STATUS_INVALID_INSTRUCTION;
    }
    if (position > state->code_size
        || count > state->code_size - position) {
        return CDISASM_STATUS_TRUNCATED;
    }
    return CDISASM_STATUS_OK;
}

static uint8_t x86_gen_mode_value(cdisasm_mode mode)
{
    return mode == CDISASM_MODE_16 ? UINT8_C(0)
        : mode == CDISASM_MODE_32 ? UINT8_C(1) : UINT8_C(2);
}

static uint8_t x86_gen_mode_mask(cdisasm_mode mode)
{
    return mode == CDISASM_MODE_16 ? UINT8_C(1)
        : mode == CDISASM_MODE_32 ? UINT8_C(2) : UINT8_C(4);
}

static uint8_t x86_gen_easz_value(unsigned int address_bits)
{
    return address_bits == 16u ? UINT8_C(1)
        : address_bits == 32u ? UINT8_C(2) : UINT8_C(3);
}

static uint8_t x86_gen_easz_mask(unsigned int address_bits)
{
    return address_bits == 16u ? UINT8_C(1)
        : address_bits == 32u ? UINT8_C(2) : UINT8_C(4);
}

static int x86_gen_vector_legacy_prefixes_valid(const x86_gen_state *state)
{
    return !state->lock_prefix
        && !state->operand_override
        && state->repeat_prefix == 0u
        && !state->rex_present
        && !state->rex2_present;
}

static void x86_gen_set_vex_destination(
    x86_gen_state *state, uint8_t prefix_byte)
{
    /* XED decode patterns retain the four low VEX.vvvv bits in their
     * encoded (inverted) form.  Lookup nonterminals invert them when they
     * construct an operand register; predicates such as VEXDEST*=1111 must
     * therefore see the raw bits here. */
    state->values[CDISASM_X86_GEN_FIELD_VEXDEST3] =
        (uint8_t)((prefix_byte >> 6) & UINT8_C(1));
    state->values[CDISASM_X86_GEN_FIELD_VEXDEST210] =
        (uint8_t)((prefix_byte >> 3) & UINT8_C(7));
}

static uint8_t x86_gen_vex_prefix_value(uint8_t prefix_byte)
{
    uint8_t pp = (uint8_t)(prefix_byte & UINT8_C(3));

    /* The encoded pp field is 00=none, 01=66, 10=F3, 11=F2.  XED's
     * VEX_PREFIX state uses the semantic prefix numbering 0=none, 1=66,
     * 2=F2, 3=F3, so the two repeat-prefix encodings must be exchanged. */
    return pp == UINT8_C(2) ? UINT8_C(3)
        : pp == UINT8_C(3) ? UINT8_C(2) : pp;
}

static cdisasm_status x86_gen_parse_prefixes(x86_gen_state *state)
{
    for (;;) {
        cdisasm_status status = x86_gen_require(state, state->position, 1u);
        uint8_t byte;
        int legacy = 1;

        if (status != CDISASM_STATUS_OK) {
            return status;
        }
        byte = state->code[state->position];
        switch (byte) {
            case UINT8_C(0xf0):
                state->prefix_flags |= CDISASM_PREFIX_LOCK;
                state->lock_prefix = 1u;
                break;
            case UINT8_C(0xf2):
                state->prefix_flags |= CDISASM_PREFIX_REPNE;
                state->repeat_prefix = UINT8_C(2);
                break;
            case UINT8_C(0xf3):
                state->prefix_flags |= CDISASM_PREFIX_REP;
                state->repeat_prefix = UINT8_C(3);
                break;
            case UINT8_C(0x66):
                state->prefix_flags |= CDISASM_PREFIX_OPERAND_SIZE;
                state->operand_override = 1u;
                break;
            case UINT8_C(0x67):
                state->prefix_flags |= CDISASM_PREFIX_ADDRESS_SIZE;
                state->address_override = 1u;
                break;
            case UINT8_C(0x26):
            case UINT8_C(0x2e):
            case UINT8_C(0x36):
            case UINT8_C(0x3e):
            case UINT8_C(0x64):
            case UINT8_C(0x65):
                state->prefix_flags |= CDISASM_PREFIX_SEGMENT;
                state->segment_prefix = byte;
                break;
            default:
                legacy = 0;
                break;
        }
        if (legacy) {
            ++state->position;
            state->rex = 0u;
            state->rex_x = 0u;
            state->rex_x4 = 0u;
            state->rex_present = 0u;
            state->values[CDISASM_X86_GEN_FIELD_REXW] = 0u;
            state->values[CDISASM_X86_GEN_FIELD_REXR] = 0u;
            state->values[CDISASM_X86_GEN_FIELD_REXB] = 0u;
            state->values[CDISASM_X86_GEN_FIELD_REXB4] = 0u;
            state->prefix_flags &= ~CDISASM_PREFIX_REX_W;
            continue;
        }
        if (state->mode == CDISASM_MODE_64
            && byte >= UINT8_C(0x40) && byte <= UINT8_C(0x4f)) {
            state->rex = byte;
            state->rex_present = 1u;
            state->prefix_flags |= CDISASM_PREFIX_REX;
            state->values[CDISASM_X86_GEN_FIELD_REXW] =
                (uint8_t)((byte >> 3) & 1u);
            state->values[CDISASM_X86_GEN_FIELD_REXR] =
                (uint8_t)((byte >> 2) & 1u);
            state->values[CDISASM_X86_GEN_FIELD_REXB] =
                (uint8_t)(byte & 1u);
            state->rex_x = (uint8_t)((byte >> 1) & 1u);
            if ((byte & UINT8_C(8)) != 0u) {
                state->prefix_flags |= CDISASM_PREFIX_REX_W;
            } else {
                state->prefix_flags &= ~CDISASM_PREFIX_REX_W;
            }
            ++state->position;
            continue;
        }
        if (state->mode == CDISASM_MODE_64 && byte == UINT8_C(0xd5)) {
            uint8_t payload;

            if (state->rex_present || state->rex2_present) {
                return CDISASM_STATUS_INVALID_INSTRUCTION;
            }
            status = x86_gen_require(state, state->position, 2u);
            if (status != CDISASM_STATUS_OK) {
                return status;
            }
            payload = state->code[state->position + 1u];
            state->position += 2u;
            state->rex2_present = 1u;
            state->rex = (uint8_t)(payload & UINT8_C(15));
            state->map = (uint8_t)((payload >> 7) & 1u);
            state->values[CDISASM_X86_GEN_FIELD_REX2] = 1u;
            state->values[CDISASM_X86_GEN_FIELD_REXR4] =
                (uint8_t)((payload >> 6) & 1u);
            state->rex_x4 = (uint8_t)((payload >> 5) & 1u);
            state->values[CDISASM_X86_GEN_FIELD_REXB4] =
                (uint8_t)((payload >> 4) & 1u);
            state->values[CDISASM_X86_GEN_FIELD_REXW] =
                (uint8_t)((payload >> 3) & 1u);
            state->values[CDISASM_X86_GEN_FIELD_REXR] =
                (uint8_t)((payload >> 2) & 1u);
            state->values[CDISASM_X86_GEN_FIELD_REXB] =
                (uint8_t)(payload & 1u);
            state->rex_x = (uint8_t)((payload >> 1) & 1u);
            state->prefix_flags |= CDISASM_PREFIX_REX2;
            if ((payload & UINT8_C(8)) != 0u) {
                state->prefix_flags |= CDISASM_PREFIX_REX_W;
            }
            break;
        }
        break;
    }

    if (state->mode == CDISASM_MODE_16) {
        state->operand_bits = state->operand_override ? 32u : 16u;
        state->address_bits = state->address_override ? 32u : 16u;
    } else if (state->mode == CDISASM_MODE_32) {
        state->operand_bits = state->operand_override ? 16u : 32u;
        state->address_bits = state->address_override ? 16u : 32u;
    } else {
        state->operand_bits = state->operand_override ? 16u : 32u;
        if ((state->rex & UINT8_C(8)) != 0u) {
            state->operand_bits = 64u;
        }
        state->address_bits = state->address_override ? 32u : 64u;
    }
    state->values[CDISASM_X86_GEN_FIELD_MODE] =
        x86_gen_mode_value(state->mode);
    state->values[CDISASM_X86_GEN_FIELD_EASZ] =
        x86_gen_easz_value(state->address_bits);
    state->values[CDISASM_X86_GEN_FIELD_REP] = state->repeat_prefix;
    state->values[CDISASM_X86_GEN_FIELD_OSZ] = state->operand_override;
    state->values[CDISASM_X86_GEN_FIELD_ASZ] = state->address_override;
    state->values[CDISASM_X86_GEN_FIELD_LOCK] = state->lock_prefix;
    return CDISASM_STATUS_OK;
}

static cdisasm_status x86_gen_parse_opcode(x86_gen_state *state)
{
    cdisasm_status status = x86_gen_require(state, state->position, 1u);
    size_t start = state->position;
    uint8_t first;

    if (status != CDISASM_STATUS_OK) {
        return status;
    }
    first = state->code[start];
    if (!state->rex2_present && first == UINT8_C(0xc5)
        && (state->mode == CDISASM_MODE_64
            || (x86_gen_require(state, start, 2u) == CDISASM_STATUS_OK
                && (state->code[start + 1u] & UINT8_C(0xc0))
                    == UINT8_C(0xc0)))) {
        uint8_t p0;

        status = x86_gen_require(state, start, 3u);
        if (status != CDISASM_STATUS_OK) {
            return status;
        }
        if (!x86_gen_vector_legacy_prefixes_valid(state)) {
            return CDISASM_STATUS_INVALID_INSTRUCTION;
        }
        p0 = state->code[start + 1u];
        state->space = CDISASM_X86_GEN_SPACE_VEX;
        state->map = 1u;
        state->opcode = state->code[start + 2u];
        state->prefix_flags |= CDISASM_PREFIX_VEX;
        state->values[CDISASM_X86_GEN_FIELD_REXR] =
            (uint8_t)((~p0 >> 7) & 1u);
        x86_gen_set_vex_destination(state, p0);
        state->values[CDISASM_X86_GEN_FIELD_VL] =
            (uint8_t)((p0 >> 2) & 1u);
        state->values[CDISASM_X86_GEN_FIELD_VEX_PREFIX] =
            x86_gen_vex_prefix_value(p0);
        state->encoding.prefix_size = (uint8_t)(start + 2u);
        state->encoding.opcode_offset = (uint8_t)(start + 2u);
        state->encoding.opcode_size = 1u;
        state->position = start + 3u;
    } else if (!state->rex2_present && first == UINT8_C(0xc4)
        && (state->mode == CDISASM_MODE_64
            || (x86_gen_require(state, start, 2u) == CDISASM_STATUS_OK
                && (state->code[start + 1u] & UINT8_C(0xc0))
                    == UINT8_C(0xc0)))) {
        uint8_t p0;
        uint8_t p1;

        status = x86_gen_require(state, start, 4u);
        if (status != CDISASM_STATUS_OK) {
            return status;
        }
        if (!x86_gen_vector_legacy_prefixes_valid(state)) {
            return CDISASM_STATUS_INVALID_INSTRUCTION;
        }
        p0 = state->code[start + 1u];
        p1 = state->code[start + 2u];
        state->space = CDISASM_X86_GEN_SPACE_VEX;
        state->map = (uint8_t)(p0 & UINT8_C(31));
        state->opcode = state->code[start + 3u];
        state->prefix_flags |= CDISASM_PREFIX_VEX;
        state->values[CDISASM_X86_GEN_FIELD_REXR] =
            (uint8_t)((~p0 >> 7) & 1u);
        state->values[CDISASM_X86_GEN_FIELD_REXB] =
            state->mode == CDISASM_MODE_64
                ? (uint8_t)((~p0 >> 5) & 1u) : 0u;
        state->rex_x = (uint8_t)((~p0 >> 6) & 1u);
        state->values[CDISASM_X86_GEN_FIELD_REXW] =
            (uint8_t)((p1 >> 7) & 1u);
        x86_gen_set_vex_destination(state, p1);
        state->values[CDISASM_X86_GEN_FIELD_VL] =
            (uint8_t)((p1 >> 2) & 1u);
        state->values[CDISASM_X86_GEN_FIELD_VEX_PREFIX] =
            x86_gen_vex_prefix_value(p1);
        state->encoding.prefix_size = (uint8_t)(start + 3u);
        state->encoding.opcode_offset = (uint8_t)(start + 3u);
        state->encoding.opcode_size = 1u;
        state->position = start + 4u;
    } else if (!state->rex2_present && first == UINT8_C(0x8f)
        && x86_gen_require(state, start, 2u) == CDISASM_STATUS_OK
        && (state->code[start + 1u] & UINT8_C(31)) >= UINT8_C(8)) {
        uint8_t p0;
        uint8_t p1;

        status = x86_gen_require(state, start, 4u);
        if (status != CDISASM_STATUS_OK) {
            return status;
        }
        if (!x86_gen_vector_legacy_prefixes_valid(state)) {
            return CDISASM_STATUS_INVALID_INSTRUCTION;
        }
        p0 = state->code[start + 1u];
        p1 = state->code[start + 2u];
        state->space = CDISASM_X86_GEN_SPACE_XOP;
        state->map = (uint8_t)(p0 & UINT8_C(31));
        state->opcode = state->code[start + 3u];
        state->prefix_flags |= CDISASM_PREFIX_XOP;
        state->values[CDISASM_X86_GEN_FIELD_REXR] =
            (uint8_t)((~p0 >> 7) & 1u);
        state->values[CDISASM_X86_GEN_FIELD_REXB] =
            state->mode == CDISASM_MODE_64
                ? (uint8_t)((~p0 >> 5) & 1u) : 0u;
        state->rex_x = (uint8_t)((~p0 >> 6) & 1u);
        state->values[CDISASM_X86_GEN_FIELD_REXW] =
            (uint8_t)((p1 >> 7) & 1u);
        x86_gen_set_vex_destination(state, p1);
        state->values[CDISASM_X86_GEN_FIELD_VL] =
            (uint8_t)((p1 >> 2) & 1u);
        state->values[CDISASM_X86_GEN_FIELD_VEX_PREFIX] =
            x86_gen_vex_prefix_value(p1);
        state->encoding.prefix_size = (uint8_t)(start + 3u);
        state->encoding.opcode_offset = (uint8_t)(start + 3u);
        state->encoding.opcode_size = 1u;
        state->position = start + 4u;
    } else if (!state->rex2_present && first == UINT8_C(0x62)
        && (state->mode == CDISASM_MODE_64
            || (x86_gen_require(state, start, 2u) == CDISASM_STATUS_OK
                && (state->code[start + 1u] & UINT8_C(0xc0))
                    == UINT8_C(0xc0)))) {
        uint8_t p0;
        uint8_t p1;
        uint8_t p2;

        status = x86_gen_require(state, start, 5u);
        if (status != CDISASM_STATUS_OK) {
            return status;
        }
        if (!x86_gen_vector_legacy_prefixes_valid(state)) {
            return CDISASM_STATUS_INVALID_INSTRUCTION;
        }
        p0 = state->code[start + 1u];
        p1 = state->code[start + 2u];
        p2 = state->code[start + 3u];
        state->space = CDISASM_X86_GEN_SPACE_EVEX;
        state->map = (uint8_t)(p0 & UINT8_C(7));
        state->opcode = state->code[start + 4u];
        state->prefix_flags |= CDISASM_PREFIX_EVEX;
        /* XED names the ordinary +8 extension REXR (P0 bit 7 inverted)
         * and the +16 extension REXR4 (P0 bit 4 inverted). */
        if (state->mode == CDISASM_MODE_64) {
            state->values[CDISASM_X86_GEN_FIELD_REXR] =
                (uint8_t)((~p0 >> 7) & 1u);
            state->values[CDISASM_X86_GEN_FIELD_REXR4] =
                (uint8_t)((~p0 >> 4) & 1u);
            state->values[CDISASM_X86_GEN_FIELD_REXB] =
                (uint8_t)((~p0 >> 5) & 1u);
            state->rex_x = (uint8_t)((~p0 >> 6) & 1u);
            state->values[CDISASM_X86_GEN_FIELD_REXB4] =
                (uint8_t)((p0 >> 3) & 1u);
        }
        state->values[CDISASM_X86_GEN_FIELD_REXW] =
            (uint8_t)((p1 >> 7) & 1u);
        x86_gen_set_vex_destination(state, p1);
        state->values[CDISASM_X86_GEN_FIELD_VEXDEST4] =
            (uint8_t)((~p2 >> 3) & 1u);
        if (state->mode != CDISASM_MODE_64
            && state->values[CDISASM_X86_GEN_FIELD_VEXDEST4] != 0u) {
            return CDISASM_STATUS_INVALID_INSTRUCTION;
        }
        state->values[CDISASM_X86_GEN_FIELD_VEX_PREFIX] =
            x86_gen_vex_prefix_value(p1);
        state->values[CDISASM_X86_GEN_FIELD_UBIT] =
            (uint8_t)((p1 >> 2) & 1u);
        state->evex_u_raw = (uint8_t)((p1 >> 2) & 1u);
        state->values[CDISASM_X86_GEN_FIELD_VL] =
            (uint8_t)((p2 >> 5) & 3u);
        state->values[CDISASM_X86_GEN_FIELD_BCRC] =
            (uint8_t)((p2 >> 4) & 1u);
        state->values[CDISASM_X86_GEN_FIELD_ZEROING] =
            (uint8_t)((p2 >> 7) & 1u);
        state->values[CDISASM_X86_GEN_FIELD_MASK] =
            (uint8_t)(p2 & 7u);
        state->values[CDISASM_X86_GEN_FIELD_ND] =
            (uint8_t)((p2 >> 4) & 1u);
        state->values[CDISASM_X86_GEN_FIELD_NF] =
            (uint8_t)((p2 >> 2) & 1u);
        state->values[CDISASM_X86_GEN_FIELD_SCC] =
            (uint8_t)(p2 & UINT8_C(15));
        state->encoding.prefix_size = (uint8_t)(start + 4u);
        state->encoding.opcode_offset = (uint8_t)(start + 4u);
        state->encoding.opcode_size = 1u;
        state->position = start + 5u;
    } else {
        state->space = CDISASM_X86_GEN_SPACE_LEGACY;
        state->encoding.prefix_size = (uint8_t)start;
        state->encoding.opcode_offset = (uint8_t)start;
        if (state->rex2_present) {
            state->opcode = first;
            state->encoding.opcode_size = 1u;
            state->position = start + 1u;
        } else if (first != UINT8_C(0x0f)) {
            state->map = 0u;
            state->opcode = first;
            state->encoding.opcode_size = 1u;
            state->position = start + 1u;
        } else {
            status = x86_gen_require(state, start, 2u);
            if (status != CDISASM_STATUS_OK) {
                return status;
            }
            if (state->code[start + 1u] == UINT8_C(0x38)
                || state->code[start + 1u] == UINT8_C(0x3a)) {
                status = x86_gen_require(state, start, 3u);
                if (status != CDISASM_STATUS_OK) {
                    return status;
                }
                state->map = state->code[start + 1u] == UINT8_C(0x38)
                    ? 2u : 3u;
                state->opcode = state->code[start + 2u];
                state->encoding.opcode_size = 3u;
                state->position = start + 3u;
            } else if (state->code[start + 1u] == UINT8_C(0x0f)) {
                state->map = 4u;
                state->opcode = 0u;
                state->encoding.opcode_size = 2u;
                state->position = start + 2u;
            } else {
                state->map = 1u;
                state->opcode = state->code[start + 1u];
                state->encoding.opcode_size = 2u;
                state->position = start + 2u;
            }
        }
    }
    state->values[CDISASM_X86_GEN_FIELD_SRM] =
        (uint8_t)(state->opcode & 7u);
    if (state->space != CDISASM_X86_GEN_SPACE_LEGACY) {
        if (state->values[CDISASM_X86_GEN_FIELD_VEX_PREFIX] == 1u) {
            state->operand_bits = 16u;
        } else if (state->mode == CDISASM_MODE_64
            && state->values[CDISASM_X86_GEN_FIELD_REXW] != 0u) {
            state->operand_bits = 64u;
        } else {
            state->operand_bits = 32u;
        }
    }
    state->opcode_end = state->position;
    return CDISASM_STATUS_OK;
}

static cdisasm_status x86_gen_parse_modrm(x86_gen_state *state)
{
    cdisasm_status status;
    size_t position;
    uint8_t byte;
    uint8_t displacement_size = 0u;

    if (state->modrm_parsed) {
        return (cdisasm_status)state->modrm_status;
    }
    state->modrm_parsed = 1u;
    position = state->opcode_end;
    status = x86_gen_require(state, position, 1u);
    if (status != CDISASM_STATUS_OK) {
        state->modrm_status = (uint8_t)status;
        return status;
    }
    state->encoding.modrm_offset = (uint8_t)position;
    byte = state->code[position++];
    state->encoding.modrm = byte;
    state->mod = (uint8_t)(byte >> 6);
    state->reg = (uint8_t)((byte >> 3) & 7u);
    state->rm = (uint8_t)(byte & 7u);
    if (state->mod != 3u) {
        if (state->address_bits == 16u) {
            if (state->mod == 0u && state->rm == 6u) {
                displacement_size = 2u;
            } else if (state->mod == 1u) {
                displacement_size = 1u;
            } else if (state->mod == 2u) {
                displacement_size = 2u;
            }
        } else {
            if (state->rm == 4u) {
                uint8_t sib;

                status = x86_gen_require(state, position, 1u);
                if (status != CDISASM_STATUS_OK) {
                    state->modrm_status = (uint8_t)status;
                    return status;
                }
                state->encoding.sib_offset = (uint8_t)position;
                sib = state->code[position++];
                state->encoding.sib = sib;
                state->values[CDISASM_X86_GEN_FIELD_NEED_SIB] = 1u;
                if (state->mod == 0u && (sib & 7u) == 5u) {
                    displacement_size = 4u;
                }
            } else if (state->mod == 0u && state->rm == 5u) {
                displacement_size = 4u;
            }
            if (state->mod == 1u) {
                displacement_size = 1u;
            } else if (state->mod == 2u) {
                displacement_size = 4u;
            }
        }
    }
    if (displacement_size != 0u) {
        status = x86_gen_require(state, position, displacement_size);
        if (status != CDISASM_STATUS_OK) {
            state->modrm_status = (uint8_t)status;
            return status;
        }
        state->encoding.displacement_offset = (uint8_t)position;
        state->encoding.displacement_size = displacement_size;
        position += displacement_size;
    }
    state->modrm_end = position;
    state->modrm_status = (uint8_t)CDISASM_STATUS_OK;
    return CDISASM_STATUS_OK;
}

static const cdisasm_x86_gen_bucket *x86_gen_find_bucket(
    uint8_t space, uint8_t map, uint8_t opcode)
{
    uint32_t wanted = ((uint32_t)space << 16)
        | ((uint32_t)map << 8) | opcode;
    size_t low = 0u;
    size_t high = CDISASM_X86_GEN_RECOGNITION_BUCKET_COUNT;

    while (low < high) {
        size_t middle = low + (high - low) / 2u;
        const cdisasm_x86_gen_bucket *bucket =
            &cdisasm_x86_gen_buckets[middle];
        uint32_t key = ((uint32_t)bucket->space << 16)
            | ((uint32_t)bucket->map << 8) | bucket->opcode;

        if (key < wanted) {
            low = middle + 1u;
        } else {
            high = middle;
        }
    }
    if (low >= CDISASM_X86_GEN_RECOGNITION_BUCKET_COUNT) {
        return NULL;
    }
    if (cdisasm_x86_gen_buckets[low].space != space
        || cdisasm_x86_gen_buckets[low].map != map
        || cdisasm_x86_gen_buckets[low].opcode != opcode) {
        return NULL;
    }
    return &cdisasm_x86_gen_buckets[low];
}

static int x86_gen_predicates_match(
    const x86_gen_state *state,
    const cdisasm_x86_gen_descriptor *descriptor)
{
    uint32_t index;

    if (descriptor->first_predicate + descriptor->predicate_count
        > CDISASM_X86_GEN_RECOGNITION_PREDICATE_COUNT) {
        return 0;
    }
    for (index = 0u; index < descriptor->predicate_count; ++index) {
        const cdisasm_x86_gen_predicate *predicate =
            &cdisasm_x86_gen_predicates[
                descriptor->first_predicate + index];
        uint8_t value;
        int equal;

        if (predicate->field >= sizeof(state->values)) {
            return 0;
        }
        value = state->values[predicate->field];
        if (predicate->field == CDISASM_X86_GEN_FIELD_UBIT
            && state->space == CDISASM_X86_GEN_SPACE_EVEX
            && state->mode == CDISASM_MODE_64
            && (descriptor->flags & CDISASM_X86_GEN_FLAG_HAS_MODRM) != 0u
            && state->mod != 3u
            && state->evex_u_raw == 0u) {
            /* APX memory addressing reinterprets the raw EVEX U bit as
             * inverted X4, then presents canonical UBIT=1 to the decode
             * pattern (matching XED's late_evex_scanner).  Admission below
             * independently requires APX when this extends a pre-APX EVEX
             * descriptor. */
            value = 1u;
        }
        equal = value == predicate->value;
        if (equal == (predicate->not_equal != 0u)) {
            return 0;
        }
    }
    return 1;
}

static int x86_gen_descriptor_is_native_apx(
    const cdisasm_x86_gen_descriptor *descriptor)
{
    return (descriptor->flags
        & (CDISASM_X86_GEN_FLAG_EVAPX
            | CDISASM_X86_GEN_FLAG_EVAPX_SCC)) != 0u;
}

static int x86_gen_descriptor_is_fp16(
    const cdisasm_x86_gen_descriptor *descriptor)
{
    /* AVX512-FP16 uses raw EVEX.U=0 for its memory encodings.  That is a
     * legacy FP16 encoding choice, not the optional APX inverted-X4 form.
     * Keep the group test numeric and string-free so the generated decoder
     * remains independent of mnemonic/IFORM text tables. */
    switch (descriptor->group_id) {
    case CDISASM_X86_GROUP_AVX512_FP16_128:
    case CDISASM_X86_GROUP_AVX512_FP16_128N:
    case CDISASM_X86_GROUP_AVX512_FP16_256:
    case CDISASM_X86_GROUP_AVX512_FP16_512:
    case CDISASM_X86_GROUP_AVX512_FP16_CONVERT_128:
    case CDISASM_X86_GROUP_AVX512_FP16_CONVERT_256:
    case CDISASM_X86_GROUP_AVX512_FP16_CONVERT_512:
    case CDISASM_X86_GROUP_AVX512_FP16_SCALAR:
        return 1;
    default:
        return 0;
    }
}

static int x86_gen_uses_optional_apx_extension(
    const x86_gen_state *state,
    const cdisasm_x86_gen_descriptor *descriptor)
{
    if (state->space != CDISASM_X86_GEN_SPACE_EVEX
        || x86_gen_descriptor_is_native_apx(descriptor)) {
        return 0;
    }
    /* With APX enabled XED reads P0 bit 3 as B4 and, for memory forms,
     * reinterprets a raw U=0 as inverted X4.  EVEXR4_ONE similarly gains a
     * second APX rule so scalar EVEX-to-GPR forms can address R16-R31. */
    return state->values[CDISASM_X86_GEN_FIELD_REXB4] != 0u
        || ((descriptor->flags & CDISASM_X86_GEN_FLAG_HAS_MODRM) != 0u
            && state->mod != 3u && state->evex_u_raw == 0u
            && !x86_gen_descriptor_is_fp16(descriptor))
        || ((descriptor->special_flags
                & CDISASM_X86_GEN_SPECIAL_EVEX_R4_APX) != 0u
            && state->values[CDISASM_X86_GEN_FIELD_REXR4] != 0u);
}

static int x86_gen_descriptor_is_apx(
    const x86_gen_state *state,
    const cdisasm_x86_gen_descriptor *descriptor)
{
    return state->rex2_present
        || x86_gen_descriptor_is_native_apx(descriptor)
        || x86_gen_uses_optional_apx_extension(state, descriptor);
}

static int x86_gen_special_fields_match(
    const x86_gen_state *state,
    const cdisasm_x86_gen_descriptor *descriptor)
{
    uint8_t mask = state->values[CDISASM_X86_GEN_FIELD_MASK];
    uint8_t zeroing = state->values[CDISASM_X86_GEN_FIELD_ZEROING];
    uint8_t mask_flags = descriptor->special_flags
        & (CDISASM_X86_GEN_SPECIAL_MASK_OPTIONAL
            | CDISASM_X86_GEN_SPECIAL_MASK_REQUIRED);

    if ((descriptor->special_flags & CDISASM_X86_GEN_SPECIAL_MASK_REQUIRED)
            != 0u
        && mask == 0u) {
        return 0;
    }
    if (state->space == CDISASM_X86_GEN_SPACE_EVEX
        && (descriptor->flags
            & (CDISASM_X86_GEN_FLAG_EVAPX
                | CDISASM_X86_GEN_FLAG_EVAPX_SCC)) == 0u) {
        if (mask_flags == 0u && mask != 0u) {
            return 0;
        }
        if (zeroing != 0u
            && (descriptor->special_flags
                & CDISASM_X86_GEN_SPECIAL_ZEROING_ALLOWED) == 0u) {
            return 0;
        }
        if (zeroing != 0u && mask == 0u) {
            return 0;
        }
    }
    return 1;
}

static unsigned int x86_gen_operand_bits(
    const x86_gen_state *state,
    const cdisasm_x86_gen_descriptor *descriptor)
{
    uint8_t policy = descriptor->operand_size_policy;

    /* APX N3's mandatory 66 spelling selects the 64-bit GPR form; it is
     * not the legacy operand-size override.  Fixed-width byte/word recipes
     * are unaffected because their recipe width wins below. */
    if ((descriptor->special_flags
            & CDISASM_X86_GEN_SPECIAL_DEFAULT_FLAGS) != 0u
        && state->mode == CDISASM_MODE_64
        && state->values[CDISASM_X86_GEN_FIELD_VEX_PREFIX] == 1u
        && state->values[CDISASM_X86_GEN_FIELD_REXW] != 0u) {
        return 64u;
    }

    if ((policy & CDISASM_X86_GEN_SIZE_FORCE64) != 0u) {
        return 64u;
    }
    if ((policy & CDISASM_X86_GEN_SIZE_CR_WIDTH) != 0u) {
        return state->mode == CDISASM_MODE_64 ? 64u : 32u;
    }
    if (state->mode == CDISASM_MODE_64
        && (policy & CDISASM_X86_GEN_SIZE_IMMUNE66_LOOP64) != 0u) {
        return 64u;
    }
    if ((policy & CDISASM_X86_GEN_SIZE_IMMUNE66) != 0u) {
        if (state->mode == CDISASM_MODE_64
            && state->values[CDISASM_X86_GEN_FIELD_REXW] != 0u) {
            return 64u;
        }
        return 32u;
    }
    if ((policy & CDISASM_X86_GEN_SIZE_IGNORE66) != 0u) {
        if (state->mode == CDISASM_MODE_16) {
            return 16u;
        }
        if (state->mode == CDISASM_MODE_32) {
            return 32u;
        }
        if ((policy & CDISASM_X86_GEN_SIZE_IMMUNE_REXW) == 0u
            && state->values[CDISASM_X86_GEN_FIELD_REXW] != 0u) {
            return 64u;
        }
        return (descriptor->flags & CDISASM_X86_GEN_FLAG_DEFAULT_64) != 0u
            ? 64u : 32u;
    }
    if ((policy & CDISASM_X86_GEN_SIZE_IMMUNE_REXW) != 0u) {
        if (state->mode == CDISASM_MODE_16) {
            return state->operand_override ? 32u : 16u;
        }
        if (state->mode == CDISASM_MODE_64
            && state->operand_override
            && state->values[CDISASM_X86_GEN_FIELD_REXW] != 0u) {
            return 32u;
        }
        return state->operand_override ? 16u : 32u;
    }
    if (state->mode == CDISASM_MODE_64
        && (descriptor->flags & CDISASM_X86_GEN_FLAG_DEFAULT_64) != 0u
        && !state->operand_override
        && state->values[CDISASM_X86_GEN_FIELD_REXW] == 0u) {
        return 64u;
    }
    return state->operand_bits;
}

static size_t x86_gen_immediate_size(
    const x86_gen_state *state,
    const cdisasm_x86_gen_descriptor *descriptor,
    uint8_t recipe)
{
    switch (recipe) {
        case CDISASM_X86_GEN_IMM_NONE:
            return 0u;
        case CDISASM_X86_GEN_IMM_8:
        case CDISASM_X86_GEN_REL_8:
            return 1u;
        case CDISASM_X86_GEN_IMM_16:
            return 2u;
        case CDISASM_X86_GEN_IMM_32:
        case CDISASM_X86_GEN_REL_32:
            return 4u;
        case CDISASM_X86_GEN_IMM_64:
        case CDISASM_X86_GEN_REL_64:
            return 8u;
        case CDISASM_X86_GEN_IMM_V:
            return x86_gen_operand_bits(state, descriptor) / 8u;
        case CDISASM_X86_GEN_IMM_Z:
        case CDISASM_X86_GEN_REL_Z:
            if ((descriptor->special_flags
                    & CDISASM_X86_GEN_SPECIAL_DEFAULT_FLAGS) != 0u
                && state->values[CDISASM_X86_GEN_FIELD_VEX_PREFIX] == 1u
                && state->values[CDISASM_X86_GEN_FIELD_REXW] == 0u) {
                /* APX N3 keeps a 64-bit GPR operand with the 16-bit
                 * immediate form selected by its mandatory 66 encoding. */
                return 2u;
            }
            return x86_gen_operand_bits(state, descriptor) == 16u ? 2u : 4u;
        case CDISASM_X86_GEN_MEMDISP_V:
            return state->address_bits / 8u;
        default:
            return SIZE_MAX;
    }
}

static uint64_t x86_gen_read_little_endian(
    const uint8_t *code, size_t position, size_t size)
{
    uint64_t value = 0u;
    size_t index;

    for (index = 0u; index < size; ++index) {
        value |= (uint64_t)code[position + index] << (index * 8u);
    }
    return value;
}

static int64_t x86_gen_sign_extend(uint64_t value, size_t size)
{
    unsigned int bits = (unsigned int)(size * 8u);

    if (bits >= 64u) {
        return (int64_t)value;
    }
    if ((value & (UINT64_C(1) << (bits - 1u))) != 0u) {
        value |= UINT64_MAX << bits;
    }
    return (int64_t)value;
}

static cdisasm_status x86_gen_finish_candidate(
    const x86_gen_state *state,
    const cdisasm_x86_gen_descriptor *descriptor,
    size_t base_position,
    x86_gen_candidate *candidate)
{
    cdisasm_x86_encoding encoding = state->encoding;
    uint8_t recipes[2] = {descriptor->immediate0, descriptor->immediate1};
    size_t position = base_position;
    unsigned int index;

    memset(candidate, 0, sizeof(*candidate));
    candidate->descriptor = descriptor;
    if ((descriptor->flags & CDISASM_X86_GEN_FLAG_HAS_MODRM) == 0u) {
        encoding.modrm_offset = 0u;
        encoding.modrm = 0u;
        encoding.sib_offset = 0u;
        encoding.sib = 0u;
        encoding.displacement_offset = 0u;
        encoding.displacement_size = 0u;
    }
    for (index = 0u; index < 2u; ++index) {
        uint8_t recipe = recipes[index];
        size_t size = x86_gen_immediate_size(state, descriptor, recipe);
        cdisasm_status status;

        if (size == SIZE_MAX) {
            return CDISASM_STATUS_INTERNAL_ERROR;
        }
        if (recipe == CDISASM_X86_GEN_IMM_NONE) {
            continue;
        }
        status = x86_gen_require(state, position, size);
        if (status != CDISASM_STATUS_OK) {
            return status;
        }
        if (recipe == CDISASM_X86_GEN_MEMDISP_V) {
            encoding.displacement_offset = (uint8_t)position;
            encoding.displacement_size = (uint8_t)size;
        } else {
            uint8_t immediate_index = encoding.immediate_count;

            if (immediate_index >= 2u) {
                return CDISASM_STATUS_INTERNAL_ERROR;
            }
            encoding.immediate_offset[immediate_index] = (uint8_t)position;
            encoding.immediate_size[immediate_index] = (uint8_t)size;
            ++encoding.immediate_count;
            if (recipe == CDISASM_X86_GEN_REL_8
                || recipe == CDISASM_X86_GEN_REL_Z
                || recipe == CDISASM_X86_GEN_REL_32
                || recipe == CDISASM_X86_GEN_REL_64) {
                candidate->relative_displacement = x86_gen_sign_extend(
                    x86_gen_read_little_endian(state->code, position, size),
                    size);
                candidate->has_relative = 1u;
            }
        }
        position += size;
    }
    candidate->encoding = encoding;
    candidate->length = position;
    candidate->score = descriptor->specificity;
    if (descriptor->decode_bit_id != CDISASM_X86_GEN_DECODE_BIT_NONE) {
        candidate->score += 256u;
    }
    return CDISASM_STATUS_OK;
}

static int x86_gen_cpu_and_flags_admit(
    const x86_gen_state *state,
    const cdisasm_x86_gen_descriptor *descriptor,
    cdisasm_cpu_id cpu_id,
    const cdisasm_x86_decode_flags *selected_flags,
    const cdisasm_x86_decode_flags *available_flags,
    int *caller_rejected,
    int *cpu_rejected)
{
    if (!cdisasm_x86_cpu_admits_generated_core(
            cpu_id, descriptor->name_id, descriptor->group_id)) {
        *cpu_rejected = 1;
        return 0;
    }
    if (x86_gen_uses_optional_apx_extension(state, descriptor)) {
        if (!cdisasm_decode_flags_test_bit(
                selected_flags, CDISASM_X86_DECODE_BIT_APX)) {
            *caller_rejected = 1;
            return 0;
        }
        if (!cdisasm_decode_flags_test_bit(
                available_flags, CDISASM_X86_DECODE_BIT_APX)) {
            *cpu_rejected = 1;
            return 0;
        }
    }
    if (descriptor->decode_bit_id != CDISASM_X86_GEN_DECODE_BIT_NONE) {
        if (!cdisasm_decode_flags_test_bit(
                selected_flags, descriptor->decode_bit_id)) {
            *caller_rejected = 1;
            return 0;
        }
        if (!cdisasm_decode_flags_test_bit(
                available_flags, descriptor->decode_bit_id)) {
            *cpu_rejected = 1;
            return 0;
        }
    }
    if ((descriptor->flags & CDISASM_X86_GEN_FLAG_UNDOCUMENTED) != 0u) {
        if (!cdisasm_decode_flags_test_bit(
                selected_flags, CDISASM_X86_DECODE_BIT_UNDOCUMENTED)) {
            *caller_rejected = 1;
            return 0;
        }
        if (!cdisasm_decode_flags_test_bit(
                available_flags, CDISASM_X86_DECODE_BIT_UNDOCUMENTED)) {
            *cpu_rejected = 1;
            return 0;
        }
    }
    return 1;
}

static int x86_gen_candidate_better(
    const x86_gen_candidate *candidate,
    const x86_gen_candidate *best)
{
    return best->descriptor == NULL
        || candidate->score > best->score
        || (candidate->score == best->score
            && candidate->descriptor->source_order
                < best->descriptor->source_order);
}

static uint8_t x86_gen_operand_size(
    const x86_gen_state *state,
    const cdisasm_x86_gen_descriptor *descriptor,
    const cdisasm_x86_gen_operand *recipe)
{
    unsigned int bits = x86_gen_operand_bits(state, descriptor);

    if (recipe->reg_class == CDISASM_X86_GEN_REG_ADDRESS_GPR
        || (recipe->flags & CDISASM_X86_GEN_OPERAND_ADDRESS_ONLY) != 0u) {
        bits = state->address_bits;
    }
    return bits == 16u ? recipe->size16
        : bits == 64u ? recipe->size64 : recipe->size32;
}

static uint8_t x86_gen_disp8_scale(
    const x86_gen_state *state,
    const cdisasm_x86_gen_descriptor *descriptor,
    const cdisasm_x86_gen_operand *recipe)
{
    unsigned int bits = x86_gen_operand_bits(state, descriptor);

    if ((recipe->flags & CDISASM_X86_GEN_OPERAND_ADDRESS_ONLY) != 0u) {
        bits = state->address_bits;
    }
    return bits == 16u ? recipe->disp_scale16
        : bits == 64u ? recipe->disp_scale64 : recipe->disp_scale32;
}

static cdisasm_x86_reg_id x86_gen_gpr_id(
    unsigned int index, unsigned int bits, int rex_like)
{
    if (index >= 32u) {
        return CDISASM_X86_REG_NONE;
    }
    if (index >= 16u) {
        switch (bits) {
            case 8u:
                return (cdisasm_x86_reg_id)(
                    CDISASM_X86_REG_R16B + index - 16u);
            case 16u:
                return (cdisasm_x86_reg_id)(
                    CDISASM_X86_REG_R16W + index - 16u);
            case 32u:
                return (cdisasm_x86_reg_id)(
                    CDISASM_X86_REG_R16D + index - 16u);
            case 64u:
                return (cdisasm_x86_reg_id)(
                    CDISASM_X86_REG_R16 + index - 16u);
            default:
                return CDISASM_X86_REG_NONE;
        }
    }
    if (bits == 8u) {
        if (index < 4u) {
            return (cdisasm_x86_reg_id)(CDISASM_X86_REG_AL + index);
        }
        if (index < 8u) {
            return (cdisasm_x86_reg_id)(
                (rex_like ? CDISASM_X86_REG_SPL : CDISASM_X86_REG_AH)
                + index - 4u);
        }
        return (cdisasm_x86_reg_id)(CDISASM_X86_REG_R8B + index - 8u);
    }
    if (bits == 16u) {
        return (cdisasm_x86_reg_id)(CDISASM_X86_REG_AX + index);
    }
    if (bits == 32u) {
        return (cdisasm_x86_reg_id)(CDISASM_X86_REG_EAX + index);
    }
    if (bits == 64u) {
        return (cdisasm_x86_reg_id)(CDISASM_X86_REG_RAX + index);
    }
    return CDISASM_X86_REG_NONE;
}

static unsigned int x86_gen_source_index(
    const x86_gen_state *state,
    const x86_gen_candidate *candidate,
    const cdisasm_x86_gen_operand *recipe)
{
    const cdisasm_x86_gen_descriptor *descriptor = candidate->descriptor;
    unsigned int result;
    int apx = x86_gen_descriptor_is_apx(state, descriptor);
    int extend = state->mode == CDISASM_MODE_64;
    int gpr = recipe->reg_class >= CDISASM_X86_GEN_REG_GPR8
        && recipe->reg_class <= CDISASM_X86_GEN_REG_ADDRESS_GPR;

    switch (recipe->source) {
        case CDISASM_X86_GEN_SOURCE_REG:
        case CDISASM_X86_GEN_SOURCE_REG_HIGH:
            result = state->reg
                + (extend
                    ? state->values[CDISASM_X86_GEN_FIELD_REXR] * 8u : 0u);
            if (extend && (recipe->source == CDISASM_X86_GEN_SOURCE_REG_HIGH
                || (apx && gpr))) {
                result += state->values[CDISASM_X86_GEN_FIELD_REXR4] * 16u;
            }
            return result;
        case CDISASM_X86_GEN_SOURCE_RM:
        case CDISASM_X86_GEN_SOURCE_RM_HIGH:
            result = state->rm
                + (extend
                    ? state->values[CDISASM_X86_GEN_FIELD_REXB] * 8u : 0u);
            if (extend && recipe->source == CDISASM_X86_GEN_SOURCE_RM_HIGH) {
                result += state->rex_x * 16u;
            } else if (extend && apx && gpr) {
                result += state->values[CDISASM_X86_GEN_FIELD_REXB4] * 16u;
            }
            return result;
        case CDISASM_X86_GEN_SOURCE_VVVV:
        case CDISASM_X86_GEN_SOURCE_VVVV_HIGH:
            result = (~state->values[CDISASM_X86_GEN_FIELD_VEXDEST210]) & 7u;
            if (extend) {
                result |= ((~state->values[CDISASM_X86_GEN_FIELD_VEXDEST3])
                    & 1u) << 3;
            }
            if (extend && (recipe->source == CDISASM_X86_GEN_SOURCE_VVVV_HIGH
                || (apx && gpr))) {
                result += state->values[CDISASM_X86_GEN_FIELD_VEXDEST4] * 16u;
            }
            return result;
        case CDISASM_X86_GEN_SOURCE_OPCODE:
            return (state->opcode & 7u)
                + (extend
                    ? state->values[CDISASM_X86_GEN_FIELD_REXB] * 8u : 0u)
                + (extend && apx
                    ? state->values[CDISASM_X86_GEN_FIELD_REXB4] * 16u
                    : 0u);
        case CDISASM_X86_GEN_SOURCE_IMMEDIATE_HIGH:
            if (candidate->encoding.immediate_count == 0u) {
                return UINT_MAX;
            }
            return state->code[candidate->encoding.immediate_offset[0]] >> 4;
        case CDISASM_X86_GEN_SOURCE_FIXED_ZERO:
            return 0u;
        default:
            return UINT_MAX;
    }
}

static cdisasm_x86_reg_id x86_gen_register_id(
    const x86_gen_state *state,
    const cdisasm_x86_gen_descriptor *descriptor,
    const cdisasm_x86_gen_operand *recipe,
    unsigned int index)
{
    uint8_t size = x86_gen_operand_size(state, descriptor, recipe);
    unsigned int bits = size == CDISASM_X86_OPERAND_SIZE_VARIABLE
        ? 0u : (unsigned int)size * 8u;

    switch (recipe->reg_class) {
        case CDISASM_X86_GEN_REG_GPR8:
            bits = 8u;
            break;
        case CDISASM_X86_GEN_REG_GPR16:
            bits = 16u;
            break;
        case CDISASM_X86_GEN_REG_GPR32:
            bits = 32u;
            break;
        case CDISASM_X86_GEN_REG_GPR64:
            bits = 64u;
            break;
        case CDISASM_X86_GEN_REG_ADDRESS_GPR:
            bits = state->address_bits;
            break;
        case CDISASM_X86_GEN_REG_GPRV:
        case CDISASM_X86_GEN_REG_GPRY:
        case CDISASM_X86_GEN_REG_GPRZ:
            break;
        case CDISASM_X86_GEN_REG_MMX:
            return index < 8u
                ? (cdisasm_x86_reg_id)(CDISASM_X86_REG_MM0 + index)
                : CDISASM_X86_REG_NONE;
        case CDISASM_X86_GEN_REG_XMM:
            return index < 32u
                ? (cdisasm_x86_reg_id)(CDISASM_X86_REG_XMM0 + index)
                : CDISASM_X86_REG_NONE;
        case CDISASM_X86_GEN_REG_YMM:
            return index < 32u
                ? (cdisasm_x86_reg_id)(CDISASM_X86_REG_YMM0 + index)
                : CDISASM_X86_REG_NONE;
        case CDISASM_X86_GEN_REG_ZMM:
            return index < 32u
                ? (cdisasm_x86_reg_id)(CDISASM_X86_REG_ZMM0 + index)
                : CDISASM_X86_REG_NONE;
        case CDISASM_X86_GEN_REG_MASK:
            return index < 8u
                ? (cdisasm_x86_reg_id)(CDISASM_X86_REG_K0 + index)
                : CDISASM_X86_REG_NONE;
        case CDISASM_X86_GEN_REG_BND:
            return index < 4u
                ? (cdisasm_x86_reg_id)(CDISASM_X86_REG_BND0 + index)
                : CDISASM_X86_REG_NONE;
        case CDISASM_X86_GEN_REG_TMM:
            return index < 8u
                ? (cdisasm_x86_reg_id)(CDISASM_X86_REG_TMM0 + index)
                : CDISASM_X86_REG_NONE;
        case CDISASM_X86_GEN_REG_X87:
            return index < 8u
                ? (cdisasm_x86_reg_id)(CDISASM_X86_REG_ST0 + index)
                : CDISASM_X86_REG_NONE;
        case CDISASM_X86_GEN_REG_SEGMENT:
            return index < 6u
                ? (cdisasm_x86_reg_id)(CDISASM_X86_REG_ES + index)
                : CDISASM_X86_REG_NONE;
        case CDISASM_X86_GEN_REG_CR:
            return index < 16u
                ? (cdisasm_x86_reg_id)(CDISASM_X86_REG_CR0 + index)
                : CDISASM_X86_REG_NONE;
        case CDISASM_X86_GEN_REG_DR:
            return index < 16u
                ? (cdisasm_x86_reg_id)(CDISASM_X86_REG_DR0 + index)
                : CDISASM_X86_REG_NONE;
        default:
            return CDISASM_X86_REG_NONE;
    }
    return x86_gen_gpr_id(
        index, bits,
        state->rex_present || state->rex2_present
            || state->space != CDISASM_X86_GEN_SPACE_LEGACY);
}

static cdisasm_x86_reg_id x86_gen_segment_prefix_id(uint8_t prefix)
{
    switch (prefix) {
        case UINT8_C(0x26): return CDISASM_X86_REG_ES;
        case UINT8_C(0x2e): return CDISASM_X86_REG_CS;
        case UINT8_C(0x36): return CDISASM_X86_REG_SS;
        case UINT8_C(0x3e): return CDISASM_X86_REG_DS;
        case UINT8_C(0x64): return CDISASM_X86_REG_FS;
        case UINT8_C(0x65): return CDISASM_X86_REG_GS;
        default: return CDISASM_X86_REG_NONE;
    }
}

static cdisasm_x86_reg_id x86_gen_vsib_id(
    uint8_t vsib_class, unsigned int index)
{
    if (index >= 32u) {
        return CDISASM_X86_REG_NONE;
    }
    if (vsib_class == CDISASM_X86_GEN_VSIB_XMM) {
        return (cdisasm_x86_reg_id)(CDISASM_X86_REG_XMM0 + index);
    }
    if (vsib_class == CDISASM_X86_GEN_VSIB_YMM) {
        return (cdisasm_x86_reg_id)(CDISASM_X86_REG_YMM0 + index);
    }
    if (vsib_class == CDISASM_X86_GEN_VSIB_ZMM) {
        return (cdisasm_x86_reg_id)(CDISASM_X86_REG_ZMM0 + index);
    }
    return CDISASM_X86_REG_NONE;
}

static void x86_gen_set_displacement(
    const x86_gen_state *state,
    const x86_gen_candidate *candidate,
    const cdisasm_x86_gen_operand *recipe,
    cdisasm_opcode *operand,
    int absolute16)
{
    uint8_t size = candidate->encoding.displacement_size;

    if (size != 0u) {
        uint64_t raw = x86_gen_read_little_endian(
            state->code, candidate->encoding.displacement_offset, size);
        int64_t displacement = absolute16
            ? (int64_t)raw : x86_gen_sign_extend(raw, size);

        if (size == 1u && state->space == CDISASM_X86_GEN_SPACE_EVEX) {
            uint8_t scale = x86_gen_disp8_scale(
                state, candidate->descriptor, recipe);
            if ((recipe->flags & CDISASM_X86_GEN_OPERAND_BROADCAST) != 0u
                && state->values[CDISASM_X86_GEN_FIELD_BCRC] != 0u
                && recipe->element_size != 0u) {
                scale = recipe->element_size;
            }
            displacement *= scale;
        }
        operand->flags |= CDISASM_OPERAND_FLAG_HAS_DISPLACEMENT;
        operand->imm = (uint64_t)displacement;
    }
}

static int x86_gen_fill_memory_operand(
    const x86_gen_state *state,
    const x86_gen_candidate *candidate,
    const cdisasm_x86_gen_operand *recipe,
    uint64_t address,
    cdisasm_opcode *operand)
{
    const cdisasm_x86_gen_descriptor *descriptor = candidate->descriptor;
    int apx = x86_gen_descriptor_is_apx(state, descriptor);

    operand->type = CDISASM_OPERAND_MEMORY;
    operand->size = x86_gen_operand_size(state, descriptor, recipe);
    operand->access = recipe->access;
    operand->segment_reg =
        (descriptor->special_flags & CDISASM_X86_GEN_SPECIAL_REMOVE_SEGMENT)
            != 0u
        ? CDISASM_X86_REG_NONE
        : x86_gen_segment_prefix_id(state->segment_prefix);
    if (operand->segment_reg != CDISASM_X86_REG_NONE) {
        operand->flags |= CDISASM_OPERAND_FLAG_EXPLICIT_SEGMENT;
    }
    if ((recipe->flags & CDISASM_X86_GEN_OPERAND_ADDRESS_ONLY) != 0u) {
        operand->flags |= CDISASM_OPERAND_FLAG_ADDRESS_ONLY;
    }
    if (recipe->source == CDISASM_X86_GEN_SOURCE_ABSOLUTE_MEMORY) {
        uint8_t displacement_size = candidate->encoding.displacement_size;
        uint64_t raw;

        if (displacement_size == 0u) {
            return 0;
        }
        raw = x86_gen_read_little_endian(
            state->code, candidate->encoding.displacement_offset,
            displacement_size);
        operand->flags |= CDISASM_OPERAND_FLAG_HAS_DISPLACEMENT
            | CDISASM_OPERAND_FLAG_ABSOLUTE
            | CDISASM_OPERAND_FLAG_HAS_ADDRESS;
        operand->imm = raw;
        operand->address = raw;
        return 1;
    }
    if (recipe->source != CDISASM_X86_GEN_SOURCE_MODRM_MEMORY
        || state->mod == 3u) {
        return 0;
    }
    if (state->address_bits == 16u) {
        static const int8_t bases[8] = {3, 3, 5, 5, 6, 7, 5, 3};
        static const int8_t indexes[8] = {6, 7, 6, 7, -1, -1, -1, -1};

        if (state->mod == 0u && state->rm == 6u) {
            uint64_t raw = x86_gen_read_little_endian(
                state->code, candidate->encoding.displacement_offset, 2u);
            operand->flags |= CDISASM_OPERAND_FLAG_ABSOLUTE
                | CDISASM_OPERAND_FLAG_HAS_ADDRESS;
            operand->address = raw;
            x86_gen_set_displacement(state, candidate, recipe, operand, 1);
        } else {
            operand->base_reg = x86_gen_gpr_id(
                (unsigned int)bases[state->rm], 16u, 1);
            if (indexes[state->rm] >= 0) {
                operand->index_reg = x86_gen_gpr_id(
                    (unsigned int)indexes[state->rm], 16u, 1);
                operand->scale = 1u;
            }
            x86_gen_set_displacement(state, candidate, recipe, operand, 0);
        }
    } else if (candidate->encoding.sib_offset != 0u) {
        uint8_t sib = candidate->encoding.sib;
        unsigned int index3 = (sib >> 3) & 7u;
        unsigned int base3 = sib & 7u;
        unsigned int index = index3
            + (state->mode == CDISASM_MODE_64 ? state->rex_x * 8u : 0u);
        unsigned int base = base3
            + state->values[CDISASM_X86_GEN_FIELD_REXB] * 8u;

        if (descriptor->vsib_class != CDISASM_X86_GEN_VSIB_NONE) {
            index += state->values[CDISASM_X86_GEN_FIELD_VEXDEST4] * 16u;
            operand->index_reg = x86_gen_vsib_id(descriptor->vsib_class, index);
            if (operand->index_reg == CDISASM_X86_REG_NONE) {
                return 0;
            }
            operand->scale = (uint8_t)(1u << (sib >> 6));
        } else {
            unsigned int index_high = state->rex2_present
                ? state->rex_x4 * 16u
                : (apx ? ((~state->evex_u_raw) & 1u) * 16u : 0u);
            index += index_high;
            if (index3 != 4u
                || (state->mode == CDISASM_MODE_64 && state->rex_x != 0u)
                || index_high != 0u) {
                operand->index_reg = x86_gen_gpr_id(
                    index, state->address_bits, 1);
                if (operand->index_reg == CDISASM_X86_REG_NONE) {
                    return 0;
                }
                operand->scale = (uint8_t)(1u << (sib >> 6));
            }
        }
        if (state->mod == 0u && base3 == 5u) {
            if (operand->index_reg == CDISASM_X86_REG_NONE) {
                operand->flags |= CDISASM_OPERAND_FLAG_ABSOLUTE
                    | CDISASM_OPERAND_FLAG_HAS_ADDRESS;
            }
        } else {
            if (state->rex2_present || apx) {
                base += state->values[CDISASM_X86_GEN_FIELD_REXB4] * 16u;
            }
            operand->base_reg = x86_gen_gpr_id(
                base, state->address_bits, 1);
            if (operand->base_reg == CDISASM_X86_REG_NONE) {
                return 0;
            }
        }
        x86_gen_set_displacement(state, candidate, recipe, operand, 0);
        if ((operand->flags & CDISASM_OPERAND_FLAG_ABSOLUTE) != 0u) {
            operand->address = state->address_bits == 64u
                ? operand->imm
                : (uint32_t)x86_gen_read_little_endian(
                    state->code, candidate->encoding.displacement_offset,
                    candidate->encoding.displacement_size);
        }
    } else if (state->mod == 0u && state->rm == 5u) {
        x86_gen_set_displacement(state, candidate, recipe, operand, 0);
        if (state->mode == CDISASM_MODE_64) {
            operand->base_reg = state->address_bits == 32u
                ? CDISASM_X86_REG_EIP : CDISASM_X86_REG_RIP;
            operand->flags |= CDISASM_OPERAND_FLAG_PC_RELATIVE
                | CDISASM_OPERAND_FLAG_HAS_ADDRESS;
            operand->address = address + candidate->length + operand->imm;
            if (state->address_bits == 32u) {
                operand->address = (uint32_t)operand->address;
            }
        } else {
            uint64_t raw = x86_gen_read_little_endian(
                state->code, candidate->encoding.displacement_offset,
                candidate->encoding.displacement_size);
            operand->flags |= CDISASM_OPERAND_FLAG_ABSOLUTE
                | CDISASM_OPERAND_FLAG_HAS_ADDRESS;
            operand->address = (uint32_t)raw;
        }
    } else {
        unsigned int base = state->rm
            + state->values[CDISASM_X86_GEN_FIELD_REXB] * 8u;

        if (state->rex2_present || apx) {
            base += state->values[CDISASM_X86_GEN_FIELD_REXB4] * 16u;
        }
        operand->base_reg = x86_gen_gpr_id(base, state->address_bits, 1);
        if (operand->base_reg == CDISASM_X86_REG_NONE) {
            return 0;
        }
        x86_gen_set_displacement(state, candidate, recipe, operand, 0);
    }
    if ((recipe->flags & CDISASM_X86_GEN_OPERAND_BROADCAST) != 0u
        && state->values[CDISASM_X86_GEN_FIELD_BCRC] != 0u) {
        operand->size = recipe->element_size;
        operand->broadcast = recipe->broadcast_count;
    }
    return 1;
}

static int x86_gen_build_operands(
    const x86_gen_state *state,
    const x86_gen_candidate *candidate,
    uint64_t address,
    cdisasm_instruction *instruction)
{
    const cdisasm_x86_gen_descriptor *descriptor = candidate->descriptor;
    uint32_t index;

    if (descriptor->first_operand + descriptor->operand_count
        > CDISASM_X86_GEN_RECOGNITION_OPERAND_COUNT) {
        return 0;
    }
    instruction->operand_count = descriptor->operand_count;
    for (index = 0u; index < descriptor->operand_count; ++index) {
        const cdisasm_x86_gen_operand *recipe =
            &cdisasm_x86_gen_operands[descriptor->first_operand + index];
        cdisasm_opcode *operand = &instruction->opcode[index];

        operand->access = recipe->access;
        if ((recipe->flags & CDISASM_X86_GEN_OPERAND_IMPLICIT) != 0u) {
            operand->flags |= CDISASM_OPERAND_FLAG_IMPLICIT;
        }
        if (recipe->kind == CDISASM_X86_GEN_OPERAND_REGISTER) {
            unsigned int register_index = 0u;

            if (recipe->source == CDISASM_X86_GEN_SOURCE_FIXED_REGISTER) {
                operand->reg = (cdisasm_x86_reg_id)recipe->literal;
            } else {
                register_index = x86_gen_source_index(
                    state, candidate, recipe);
                operand->reg = x86_gen_register_id(
                    state, descriptor, recipe, register_index);
            }
            if ((recipe->source != CDISASM_X86_GEN_SOURCE_FIXED_REGISTER
                    && register_index == UINT_MAX)
                || operand->reg == CDISASM_X86_REG_NONE
                || operand->reg >= CDISASM_X86_REG_COUNT
                || ((recipe->flags & CDISASM_X86_GEN_OPERAND_NO_RSP) != 0u
                    && operand->reg == CDISASM_X86_REG_RSP)) {
                return 0;
            }
            operand->type = CDISASM_OPERAND_REGISTER;
            operand->size = x86_gen_operand_size(state, descriptor, recipe);
        } else if (recipe->kind == CDISASM_X86_GEN_OPERAND_MEMORY) {
            if (!x86_gen_fill_memory_operand(
                    state, candidate, recipe, address, operand)) {
                return 0;
            }
        } else if (recipe->kind
                   == CDISASM_X86_GEN_OPERAND_LITERAL_IMMEDIATE) {
            operand->type = CDISASM_OPERAND_IMMEDIATE;
            operand->size = x86_gen_operand_size(
                state, descriptor, recipe);
            operand->imm = recipe->literal;
        } else {
            uint8_t immediate_index = recipe->immediate_index;
            uint8_t size;
            uint64_t raw;

            if (immediate_index >= candidate->encoding.immediate_count) {
                return 0;
            }
            size = candidate->encoding.immediate_size[immediate_index];
            raw = x86_gen_read_little_endian(
                state->code,
                candidate->encoding.immediate_offset[immediate_index], size);
            operand->type = CDISASM_OPERAND_IMMEDIATE;
            operand->size = size;
            operand->access = recipe->access;
            if ((recipe->flags & CDISASM_X86_GEN_OPERAND_SIGNED) != 0u) {
                operand->flags |= CDISASM_OPERAND_FLAG_SIGNED;
                operand->imm = (uint64_t)x86_gen_sign_extend(raw, size);
            } else {
                operand->imm = raw;
            }
            if (recipe->kind == CDISASM_X86_GEN_OPERAND_RELATIVE) {
                int64_t displacement = x86_gen_sign_extend(raw, size);
                uint64_t target = address + candidate->length
                    + (uint64_t)displacement;

                operand->flags |= CDISASM_OPERAND_FLAG_PC_RELATIVE
                    | CDISASM_OPERAND_FLAG_HAS_ADDRESS
                    | CDISASM_OPERAND_FLAG_SIGNED;
                operand->address = (uint64_t)displacement;
                operand->imm = target;
                instruction->branch_target = target;
            } else if (recipe->kind
                       == CDISASM_X86_GEN_OPERAND_ABSOLUTE_BRANCH) {
                operand->flags |= CDISASM_OPERAND_FLAG_ABSOLUTE
                    | CDISASM_OPERAND_FLAG_HAS_ADDRESS;
                operand->address = raw;
                instruction->branch_target = raw;
            }
        }
    }
    return 1;
}

static int x86_gen_add_group(
    cdisasm_instruction *instruction,
    cdisasm_x86_group_id group_id)
{
    uint8_t index = 0u;
    uint8_t move;

    if (group_id < CDISASM_X86_GROUP_FIRST
        || group_id > CDISASM_X86_GROUP_LAST) {
        return 0;
    }
    while (index < instruction->x86_group_count
        && instruction->x86_group_ids[index] < group_id) {
        ++index;
    }
    if (index < instruction->x86_group_count
        && instruction->x86_group_ids[index] == group_id) {
        return 1;
    }
    if (instruction->x86_group_count >= CDISASM_MAX_X86_GROUPS) {
        return 0;
    }
    for (move = instruction->x86_group_count; move > index; --move) {
        instruction->x86_group_ids[move] =
            instruction->x86_group_ids[move - 1u];
    }
    instruction->x86_group_ids[index] = group_id;
    ++instruction->x86_group_count;
    return 1;
}

/* The compact XED family table stores the most-specific ISA_SET on each
 * descriptor.  The hand-written decoder also exposes the stable umbrella
 * groups used by callers for capability checks.  Preserve that public
 * contract for generated FP16 forms instead of forcing users to know whether
 * a form came from the fallback or the hand decoder. */
static int x86_gen_add_derived_groups(
    cdisasm_instruction *instruction,
    cdisasm_x86_group_id group_id)
{
    switch (group_id) {
    case CDISASM_X86_GROUP_AVX512_FP16_128:
    case CDISASM_X86_GROUP_AVX512_FP16_128N:
    case CDISASM_X86_GROUP_AVX512_FP16_256:
    case CDISASM_X86_GROUP_AVX512_FP16_512:
    case CDISASM_X86_GROUP_AVX512_FP16_SCALAR:
    case CDISASM_X86_GROUP_AVX512_FP16_CONVERT_128:
    case CDISASM_X86_GROUP_AVX512_FP16_CONVERT_256:
    case CDISASM_X86_GROUP_AVX512_FP16_CONVERT_512:
        return x86_gen_add_group(instruction, CDISASM_X86_GROUP_AVX)
            && x86_gen_add_group(
                instruction, CDISASM_X86_GROUP_AVX512FP16);
    case CDISASM_X86_GROUP_APX_F_ADX:
    case CDISASM_X86_GROUP_APX_F_ADX_N3:
    case CDISASM_X86_GROUP_APX_F_AMX:
    case CDISASM_X86_GROUP_APX_F_AMX_BASE:
    case CDISASM_X86_GROUP_APX_F_AMX_MOVRS:
    case CDISASM_X86_GROUP_APX_F_BMI1:
    case CDISASM_X86_GROUP_APX_F_BMI1_N3:
    case CDISASM_X86_GROUP_APX_F_BMI2:
    case CDISASM_X86_GROUP_APX_F_BMI2_N3:
    case CDISASM_X86_GROUP_APX_F_CET:
    case CDISASM_X86_GROUP_APX_F_CMPCCXADD:
    case CDISASM_X86_GROUP_APX_F_ENQCMD:
    case CDISASM_X86_GROUP_APX_F_INVPCID:
    case CDISASM_X86_GROUP_APX_F_KOPB:
    case CDISASM_X86_GROUP_APX_F_KOPD:
    case CDISASM_X86_GROUP_APX_F_KOPQ:
    case CDISASM_X86_GROUP_APX_F_KOPW:
    case CDISASM_X86_GROUP_APX_F_LZCNT:
    case CDISASM_X86_GROUP_APX_F_LZCNT_N3:
    case CDISASM_X86_GROUP_APX_F_MOVBE:
    case CDISASM_X86_GROUP_APX_F_MOVDIR64B:
    case CDISASM_X86_GROUP_APX_F_MOVDIRI:
    case CDISASM_X86_GROUP_APX_F_MOVRS:
    case CDISASM_X86_GROUP_APX_F_MSR_IMM:
    case CDISASM_X86_GROUP_APX_F_N3:
    case CDISASM_X86_GROUP_APX_F_POPCNT:
    case CDISASM_X86_GROUP_APX_F_POPCNT_N3:
    case CDISASM_X86_GROUP_APX_F_RAO_INT:
    case CDISASM_X86_GROUP_APX_F_USER_MSR:
    case CDISASM_X86_GROUP_APX_F_VMX:
        return x86_gen_add_group(instruction, CDISASM_X86_GROUP_APX_F);
    case CDISASM_X86_GROUP_AMX_INT8:
    case CDISASM_X86_GROUP_AMX_BF16:
    case CDISASM_X86_GROUP_AMX_FP16:
    case CDISASM_X86_GROUP_AMX_COMPLEX:
    case CDISASM_X86_GROUP_AMX_FP8:
    case CDISASM_X86_GROUP_AMX_MOVRS:
    case CDISASM_X86_GROUP_AMX_AVX512:
    case CDISASM_X86_GROUP_AMX_TILE_BASE:
        return x86_gen_add_group(instruction, CDISASM_X86_GROUP_AMX_TILE);
    default:
        return 1;
    }
}

static cdisasm_status x86_gen_commit(
    const x86_gen_state *state,
    const x86_gen_candidate *candidate,
    uint64_t address,
    cdisasm_instruction *instruction)
{
    const cdisasm_x86_gen_descriptor *descriptor = candidate->descriptor;

    memset(instruction, 0, sizeof(*instruction));
    instruction->address = address;
    instruction->opcode_size = (uint32_t)candidate->length;
    instruction->opcode_flags = state->prefix_flags
        | CDISASM_X86_INSTRUCTION_FLAG_GENERATED_FALLBACK;
    if ((descriptor->status_flags & CDISASM_X86_GEN_STATUS_READS_FLAGS) != 0u) {
        instruction->opcode_flags
            |= CDISASM_X86_INSTRUCTION_FLAG_READS_STATUS_FLAGS;
    }
    if ((descriptor->status_flags & CDISASM_X86_GEN_STATUS_WRITES_FLAGS) != 0u) {
        instruction->opcode_flags
            |= CDISASM_X86_INSTRUCTION_FLAG_WRITES_STATUS_FLAGS;
    }
    if (state->values[CDISASM_X86_GEN_FIELD_ND] != 0u
        && (descriptor->flags
            & (CDISASM_X86_GEN_FLAG_EVAPX
                | CDISASM_X86_GEN_FLAG_EVAPX_SCC)) != 0u) {
        instruction->opcode_flags |= CDISASM_PREFIX_APX_NDD;
    }
    if (state->values[CDISASM_X86_GEN_FIELD_NF] != 0u
        && (descriptor->flags
            & (CDISASM_X86_GEN_FLAG_EVAPX
                | CDISASM_X86_GEN_FLAG_EVAPX_SCC)) != 0u) {
        instruction->opcode_flags |= CDISASM_PREFIX_APX_NF;
    }
    instruction->name_id = descriptor->name_id;
    instruction->form_id = descriptor->iform_id;
    instruction->opcode_groups = descriptor->generic_groups;
    instruction->encoding = candidate->encoding;
    instruction->last_error_id = (uint8_t)CDISASM_STATUS_OK;
    if (descriptor->group_id >= CDISASM_X86_GROUP_FIRST
        && descriptor->group_id <= CDISASM_X86_GROUP_LAST) {
        if (!x86_gen_add_group(instruction, descriptor->group_id)) {
            return CDISASM_STATUS_INTERNAL_ERROR;
        }
        if (!x86_gen_add_derived_groups(instruction, descriptor->group_id)) {
            return CDISASM_STATUS_INTERNAL_ERROR;
        }
    }
    if (x86_gen_uses_optional_apx_extension(state, descriptor)
        && !x86_gen_add_group(instruction, CDISASM_X86_GROUP_APX_F)) {
        return CDISASM_STATUS_INTERNAL_ERROR;
    }
    if (candidate->has_relative) {
        instruction->branch_target = address + candidate->length
            + (uint64_t)candidate->relative_displacement;
    }
    if ((descriptor->special_flags
            & (CDISASM_X86_GEN_SPECIAL_MASK_OPTIONAL
                | CDISASM_X86_GEN_SPECIAL_MASK_REQUIRED)) != 0u
        && state->values[CDISASM_X86_GEN_FIELD_MASK] != 0u) {
        instruction->mask_reg = (cdisasm_x86_reg_id)(
            CDISASM_X86_REG_K0
            + state->values[CDISASM_X86_GEN_FIELD_MASK]);
        instruction->mask_mode =
            state->values[CDISASM_X86_GEN_FIELD_ZEROING] != 0u
            ? CDISASM_X86_MASK_ZERO : CDISASM_X86_MASK_MERGE;
    }
    if (state->mod == 3u
        && state->values[CDISASM_X86_GEN_FIELD_BCRC] != 0u) {
        if ((descriptor->special_flags & CDISASM_X86_GEN_SPECIAL_ROUND)
            != 0u) {
            instruction->rounding = (cdisasm_x86_rounding_mode)(
                state->values[CDISASM_X86_GEN_FIELD_VL] + 1u);
            instruction->sae = CDISASM_X86_SAE_ENABLED;
        } else if ((descriptor->special_flags & CDISASM_X86_GEN_SPECIAL_SAE)
                   != 0u) {
            instruction->sae = CDISASM_X86_SAE_ENABLED;
        }
    }
    if ((descriptor->special_flags
            & CDISASM_X86_GEN_SPECIAL_DEFAULT_FLAGS) != 0u) {
        /* APX DFV is the raw four-bit EVEX.vvvv value.  Unlike ordinary
         * register operands it is not bitwise inverted by EVEX decoding. */
        instruction->default_flags = (cdisasm_x86_default_flags)(
            ((state->values[CDISASM_X86_GEN_FIELD_VEXDEST3] & 1u) << 3)
            | (state->values[CDISASM_X86_GEN_FIELD_VEXDEST210] & 7u));
    }
    if (!x86_gen_build_operands(state, candidate, address, instruction)) {
        return CDISASM_STATUS_INVALID_INSTRUCTION;
    }
    /* MASK_AS_CONTROL forms such as VPBLENDM* preserve the destination
     * elements under merge masking.  Keep the generic XED access recipe
     * unchanged for ordinary EVEX instructions and apply the additional
     * destination read dependency only to descriptors carrying this explicit
     * semantic attribute. */
    if ((descriptor->special_flags
            & CDISASM_X86_GEN_SPECIAL_MASK_AS_CONTROL) != 0u
        && instruction->mask_mode == CDISASM_X86_MASK_MERGE
        && instruction->operand_count != 0u
        && instruction->opcode[0].access == CDISASM_OPERAND_ACCESS_WRITE) {
        instruction->opcode[0].access = CDISASM_OPERAND_ACCESS_READ_WRITE;
    }
    return CDISASM_STATUS_OK;
}

static cdisasm_status x86_gen_decode_impl(
    const uint8_t *code,
    size_t code_size,
    uint64_t address,
    cdisasm_mode mode,
    cdisasm_cpu_id cpu_id,
    const cdisasm_x86_decode_flags *selected_flags,
    cdisasm_x86_name_id required_name_id,
    cdisasm_instruction *instruction)
{
    x86_gen_state state;
    x86_gen_candidate best;
    cdisasm_x86_decode_flags available_flags;
    const cdisasm_x86_gen_bucket *bucket;
    cdisasm_status status;
    uint32_t reference_index;
    int caller_rejected = 0;
    int cpu_rejected = 0;
    int truncated = 0;

    if (code == NULL || instruction == NULL || code_size == 0u) {
        return CDISASM_STATUS_INTERNAL_ERROR;
    }
    memset(&state, 0, sizeof(state));
    memset(&best, 0, sizeof(best));
    state.code = code;
    state.code_size = code_size;
    state.mode = mode;
    status = x86_gen_parse_prefixes(&state);
    if (status != CDISASM_STATUS_OK) {
        return status;
    }
    status = x86_gen_parse_opcode(&state);
    if (status != CDISASM_STATUS_OK) {
        return status;
    }
    if (state.space == CDISASM_X86_GEN_SPACE_LEGACY && state.map == 4u) {
        status = x86_gen_parse_modrm(&state);
        if (status != CDISASM_STATUS_OK) {
            return status;
        }
        status = x86_gen_require(&state, state.modrm_end, 1u);
        if (status != CDISASM_STATUS_OK) {
            return status;
        }
        state.opcode = state.code[state.modrm_end];
        state.values[CDISASM_X86_GEN_FIELD_SRM] =
            (uint8_t)(state.opcode & 7u);
        state.encoding.selector_offset = (uint8_t)state.modrm_end;
        state.modrm_end += 1u;
    }
    bucket = x86_gen_find_bucket(state.space, state.map, state.opcode);
    if (bucket == NULL
        || bucket->first_descriptor + bucket->descriptor_count
            > CDISASM_X86_GEN_RECOGNITION_BUCKET_REF_COUNT) {
        return CDISASM_STATUS_INVALID_INSTRUCTION;
    }
    if (cdisasm_x86_cpu_decode_flag_mask(
            cpu_id, mode, &available_flags) != CDISASM_STATUS_OK) {
        return CDISASM_STATUS_INTERNAL_ERROR;
    }
    for (reference_index = 0u;
         reference_index < bucket->descriptor_count;
         ++reference_index) {
        uint16_t descriptor_index =
            cdisasm_x86_gen_bucket_descriptor_indexes[
                bucket->first_descriptor + reference_index];
        const cdisasm_x86_gen_descriptor *descriptor;
        x86_gen_candidate candidate;
        size_t base_position;

        if (descriptor_index
            >= CDISASM_X86_GEN_RECOGNITION_DESCRIPTOR_COUNT) {
            return CDISASM_STATUS_INTERNAL_ERROR;
        }
        descriptor = &cdisasm_x86_gen_descriptors[descriptor_index];
        if (required_name_id != CDISASM_X86_NAME_NONE
            && descriptor->name_id != required_name_id) {
            continue;
        }
        if ((descriptor->mode_mask & x86_gen_mode_mask(mode)) == 0u
            || (descriptor->easz_mask
                & x86_gen_easz_mask(state.address_bits)) == 0u) {
            continue;
        }
        if ((descriptor->flags & CDISASM_X86_GEN_FLAG_HAS_MODRM) != 0u) {
            status = x86_gen_parse_modrm(&state);
            if (status != CDISASM_STATUS_OK) {
                if (status == CDISASM_STATUS_TRUNCATED) {
                    truncated = 1;
                    continue;
                }
                return status;
            }
            if ((descriptor->mod_mask & (UINT8_C(1) << state.mod)) == 0u
                || (descriptor->reg_mask
                    & (UINT8_C(1) << state.reg)) == 0u
                || (descriptor->rm_mask
                    & (UINT8_C(1) << state.rm)) == 0u) {
                continue;
            }
            base_position = state.modrm_end;
        } else {
            base_position = state.opcode_end;
        }
        {
            int predicates_match = x86_gen_predicates_match(&state, descriptor);
            int special_match = x86_gen_special_fields_match(&state, descriptor);
            if (!predicates_match || !special_match) {
                continue;
            }
        }
        if ((descriptor->flags
                & (CDISASM_X86_GEN_FLAG_EVAPX
                    | CDISASM_X86_GEN_FLAG_EVAPX_SCC)) != 0u
            && state.space != CDISASM_X86_GEN_SPACE_EVEX) {
            /* Raw U=0 is valid for APX memory operands: predicate matching
             * canonicalizes it to UBIT=1 while the address decoder consumes
             * it as inverted X4.  Register forms still fail their generated
             * UBIT=1 predicate. */
            continue;
        }
        status = x86_gen_finish_candidate(
            &state, descriptor, base_position, &candidate);
        if (status != CDISASM_STATUS_OK) {
            if (status == CDISASM_STATUS_TRUNCATED) {
                truncated = 1;
                continue;
            }
            return status;
        }
        if (x86_gen_uses_optional_apx_extension(&state, descriptor)
            && mode != CDISASM_MODE_64) {
            continue;
        }
        if (!x86_gen_cpu_and_flags_admit(
                &state, descriptor, cpu_id, selected_flags, &available_flags,
                &caller_rejected, &cpu_rejected)) {
            continue;
        }
        if (x86_gen_candidate_better(&candidate, &best)) {
            best = candidate;
        }
    }
    if (best.descriptor != NULL) {
        return x86_gen_commit(&state, &best, address, instruction);
    }
    if (truncated) {
        return CDISASM_STATUS_TRUNCATED;
    }
    if (caller_rejected) {
        return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
    }
    (void)cpu_rejected;
    return CDISASM_STATUS_INVALID_INSTRUCTION;
}

cdisasm_status cdisasm_x86_decode_generated(
    const uint8_t *code,
    size_t code_size,
    uint64_t address,
    cdisasm_mode mode,
    cdisasm_cpu_id cpu_id,
    const cdisasm_x86_decode_flags *selected_flags,
    cdisasm_instruction *instruction)
{
    return x86_gen_decode_impl(
        code, code_size, address, mode, cpu_id, selected_flags,
        CDISASM_X86_NAME_NONE, instruction);
}

int cdisasm_x86_attach_generated_identity(
    const uint8_t *code,
    size_t code_size,
    uint64_t address,
    cdisasm_mode mode,
    cdisasm_cpu_id cpu_id,
    cdisasm_instruction *instruction)
{
    cdisasm_instruction generated;
    cdisasm_x86_decode_flags available_flags;
    cdisasm_x86_name_id name_id;
    uint32_t opcode_size;

    if (instruction == NULL
        || instruction->name_id == CDISASM_X86_NAME_NONE
        || cdisasm_x86_cpu_decode_flag_mask(
            cpu_id, mode, &available_flags) != CDISASM_STATUS_OK) {
        return 0;
    }
    name_id = instruction->name_id;
    opcode_size = instruction->opcode_size;
    if (x86_gen_decode_impl(
            code, code_size, address, mode, cpu_id, &available_flags,
            name_id, &generated) != CDISASM_STATUS_OK
        || generated.name_id != name_id
        || generated.opcode_size != opcode_size) {
        return 0;
    }
    instruction->form_id = generated.form_id;
    return 1;
}

#else

cdisasm_status cdisasm_x86_decode_generated(
    const uint8_t *code,
    size_t code_size,
    uint64_t address,
    cdisasm_mode mode,
    cdisasm_cpu_id cpu_id,
    const cdisasm_x86_decode_flags *selected_flags,
    cdisasm_instruction *instruction)
{
    (void)code;
    (void)code_size;
    (void)address;
    (void)mode;
    (void)cpu_id;
    (void)selected_flags;
    (void)instruction;
    return CDISASM_STATUS_UNSUPPORTED_INSTRUCTION;
}

int cdisasm_x86_attach_generated_identity(
    const uint8_t *code,
    size_t code_size,
    uint64_t address,
    cdisasm_mode mode,
    cdisasm_cpu_id cpu_id,
    cdisasm_instruction *instruction)
{
    (void)code;
    (void)code_size;
    (void)address;
    (void)mode;
    (void)cpu_id;
    (void)instruction;
    return 0;
}

#endif
