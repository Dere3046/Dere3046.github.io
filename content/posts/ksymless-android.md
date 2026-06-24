---
title: "ksymless Android"
date: 2026-06-19
draft: false
tags: ["android", "kernel", "kallsyms", "arm64", "gki"]
---

ARM64 port of [ksymless](https://github.com/rota1001/ksymless). finds
`sys_call_table` and reconstructs `kallsyms_lookup_name` on Android GKI
without exported kernel symbols.

<!--more-->

## background

Since Linux 5.7 `kallsyms_lookup_name` is no longer exported. on Android GKI
kernels this means kernel modules cannot look up symbols by name.

## solution

the module starts from a single exported symbol (`sprint_symbol`) and
rebuilds the full kallsyms lookup chain in 8 steps.

### 1. anchor

`&sprint_symbol` is a function pointer. the linker fills in the real
address via `R_AARCH64_ABS64` relocation. mask off the page offset to
get the kernel base.

```c
sprint_addr = (unsigned long)&sprint_symbol;
kernel_base = sprint_addr & ~0x1FFFFFULL;
```

### 2. sys_call_table

walk the x29 frame pointer chain out of the module init call. strip PAC
signatures from return addresses. scan backwards for `do_el0_svc` frames.

inside `do_el0_svc`, the compiler emits an ADRP+ADD+B triplet to load
`sys_call_table`:

```c
unsigned long find_sct(struct fp_ret *frames, int nf)
{
    for (int i = nf - 1; i >= 0; i--) {
        unsigned long base = frames[i].addr - 128;
        scan_adrp_add(base, MAX_SCAN, adrps, MAX_ADRP);
        for (int j = 0; j < na; j++) {
            if (!adrps[j].has_b) continue;
            if (check_sct(adrps[j].target)) {
                sys_call_table_addr = adrps[j].target;
                return adrps[j].target;
            }
        }
    }
    return 0;
}
```

`scan_adrp_add` decodes the ARM64 instructions: ADRP extracts bits 21-16
of the page address, ADD supplies the page offset, and B gives the final
target address of the instruction sequence after the ADRP+ADD pair.

### 3. BL chain

trace the BL (branch-and-link) instruction chain recursively from
`sprint_symbol`. each BL instruction at offset `i` targets
`fn + i*4 + imm26*4`. collect all visited functions (37 on this device).

```c
int follow_bl(unsigned long fn, unsigned long *visited, int *nv_cnt, int depth)
{
    for (int i = 0; i < 256; i++) {
        unsigned int insn = bl_buf[i];
        if ((insn & 0xFC000000) != 0x94000000) continue;
        long imm26 = insn & 0x3FFFFFF;
        if (imm26 & 0x2000000) imm26 |= ~0x3FFFFFF;
        unsigned long tgt = fn + i * 4 + imm26 * 4;
        if (!is_ktxt(tgt)) continue;
        visited[(*nv_cnt)++] = tgt;
        follow_bl(tgt, visited, nv_cnt, depth - 1);
    }
}
```

### 4. ADRP pages

for each visited function, scan 1024 instructions for ADRP instructions.
extract the target page: `(pc & ~0xFFF) + (imm << 12)`. collect
74 unique pages across all functions.

```c
int collect_adrp_pages(unsigned long fn, unsigned long *pages, int max)
{
    for (int i = 0; i < 256 && n < max; i++) {
        unsigned int insn = buf[i];
        if ((insn & 0x9F000000) != 0x90000000) continue;
        unsigned long imm = ((insn >> 5) & 0x7FFFF) << 2 | ((insn >> 29) & 3);
        unsigned long page = ((fn + i * 4) & ~0xFFF) + (imm << 12);
        pages[n++] = page;
    }
}
```

### 5. find klbase

scan every ADRP page for an 8-byte value matching `kernel_base`.
this value is `kallsyms_relative_base` (= `_text`).

```c
for (int pi = 0; pi < total_pages && !klbase_addr; pi++) {
    for (int off = 0; off < 0x1000; off += 8) {
        unsigned long v;
        safe_read(&v, (void *)(page + off), 8);
        if (v == kernel_base) {
            klbase_addr = page + off;
            break;
        }
    }
}
```

### 6. find kloffs

`kallsyms_offsets[0]` is always 0. the first symbol's address equals
`kallsyms_relative_base`. scan every 4-byte position in every ADRP page
for a u32 value of 0.

verify each candidate by passing the first 4 offsets through `sprint_symbol`.
the kernel's own resolver. if any returns raw hex (`0x...`) instead of a
symbol name, the candidate is rejected. `sprint_symbol` always returns the
correct answer because it uses the kernel's internal lookup path.

walk the sorted u32 sequence from each verified candidate. pick the one
with the longest run. the real `kallsyms_offsets` has `num_syms` entries
(126252 on these devices), unmatched by any other `.rodata` region.

```c
// offsets[0] is always 0 (_text - relative_base)
if (v != 0) continue;

// sprint_symbol verify: first 4 offsets must resolve to real names
for (int i = 0; i < 4 && ok; i++) {
    sprint_symbol(name, klbase_val + read_u32(addr + i * 4));
    if (name[0] == '0' && name[1] == 'x')
        ok = 0;  // sprint_symbol returned raw hex = no symbol here
}
if (!ok) continue;

// count consecutive sorted u32 entries, pick the longest
int len = 0, prev = -1;
for (int i = 0; i < 500000; i++) {
    unsigned int v = read_u32(addr + i * 4);
    if ((int)v < prev) break;
    prev = (int)v;
    len++;
}
if (len > best_len) { best_len = len; best_addr = addr; }
```

### 7. layout derivation

from the kernel source (`scripts/kallsyms.c`) the data structures are
laid out in `.rodata`:

```
num_syms (4B)
names (compressed)
markers (u32 × ceil(num_syms/256))
token_table (256 null-terminated strings)
token_index (256 × u16 = 512B)
offsets (u32 × num_syms)
relative_base (u64)
seqs_of_names (3B × num_syms)
```

all addresses are derived from `klbase` and `kloffs`:

```c
klnum_val    = (klbase_addr - kloffs_addr) / 4;   // num_syms
klindex_addr = kloffs_addr - 512;                   // token_index
klseqs_addr  = klbase_addr + 8;                     // seqs_of_names

// find klnum_addr: match value == klnum_val in ADRP pages
// find kltable_addr: backward scan from token_index for 256 strings
// compute klmarks_addr and klnames_addr from layout
```

### 8. name lookup

implement both directions:

```c
unsigned long kallsyms_name_to_addr(const char *name)
{
    int low = 0, high = (int)klnum_val - 1;
    while (low <= high) {
        int mid = low + (high - low) / 2;
        unsigned int seq = get_sym_seq(mid);      // name-sorted -> original idx
        unsigned int off = get_sym_offset(seq);    // idx -> names offset
        expand_sym(off, nbuf, sizeof(nbuf));       // decompress
        int r = strcmp(name, nbuf);
        if (r > 0) low = mid + 1;
        else if (r < 0) high = mid - 1;
        else return sym_addr(seq);                  // offsets[seq] + klbase
    }
    return 0;
}
```

verify with kprobe + `sprint_symbol`:

```c
unsigned long test_addr = resolve("kallsyms_lookup_name");
sprint_symbol_no_offset(truth, test_addr);
sym_name_at(test_addr, our, sizeof(our));                // addr -> name
unsigned long lookup = kallsyms_name_to_addr(truth);     // name -> addr
```

## conclusion

full kallsyms lookup without any exported symbol dependency.
`sym_name_at` and `kallsyms_name_to_addr` match kernel values on device.

## repo

[github.com/Dere3046/ksymless_Android](https://github.com/Dere3046/ksymless_Android)

## references

- [rota1001/ksymless](https://github.com/rota1001/ksymless) — original x86_64 technique
- [xcellerator: linux rootkits 11](https://xcellerator.github.io/posts/linux_rootkits_11/) — kallsyms internals
