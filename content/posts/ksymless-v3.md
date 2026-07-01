---
title: "ksymless v3: improving compatibility across GKI versions"
date: 2026-07-02T00:00:00+08:00
slug: "ksymless-v3"
tags: ["linux", "kernel", "kallsyms", "android"]
---

The initial version relied on ADRP instruction scanning to locate kallsyms
data. This worked on android16-6.12 but not on android15-6.6. The ADRP
window size needed depends on compiler inlining behavior, which varies
across kernel builds and cannot be sourced to a constant.

The fix is simple. Instead of hunting ADRP instructions in function bodies,
we search for the `token_index` structure directly in kernel `.rodata`. Its
layout is invariant: determined by `scripts/kallsyms.c`, identical in 6.6
and 6.12.

```c
// scripts/kallsyms.c:442-444 (6.12) / :482-484 (6.6)
output_label("kallsyms_token_index");
for (i = 0; i < 256; i++)
    printf("\t.short\t%d\n", best_idx[i]);
// best_idx[i] = accumulated byte offset into token_table
// -> token_index[0] = 0, strictly increasing, 256 entries of u16

// scripts/kallsyms.c:447 (6.12) / :490 (6.6)
output_label("kallsyms_offsets");
for (i = 0; i < table_cnt; i++) {
    offset = table[i]->addr - relative_base;     // :460-461
    printf("\t.long\t%#x\n", (int)offset);
}
// -> offsets[0] = 0, N entries of u32, strictly non-decreasing
```

The `token_index` signature is unique: 256 consecutive `u16` values,
strictly increasing, starting at 0.

```
P(random 256 u16 monotonic | idx[0]=0) = 1/256! ~ 10^-506
```

Once found, `kallsyms_offsets` is exactly 512 bytes after `token_index`
(plus `.balign 8` padding from `scripts/kallsyms.c:362`).

The search is self-terminating. `safe_read` (backed by
`copy_from_kernel_nofault` in `mm/maccess.c:24-46`) returns `-EFAULT` on
unmapped pages, so the scan naturally stops at the kernel image boundary.
The starting point is always in `.text`: `kernel_base + 1MB` is beyond
`_stext`, since `.head.text` is capped at 64KB by `SEGMENT_ALIGN`
(`arch/arm64/include/asm/memory.h:171`), and `.text` is tens of megabytes
long.

```c
// boot.h:18  --  MIN_KIMG_ALIGN = SZ_2M
// memory.h:171  --  SEGMENT_ALIGN = SZ_64K
kernel_base = (unsigned long)&sprint_symbol & ~0x1FFFFFULL;
```

That is it. No ADRP scanning, no BL chain, no window sizes to guess.

```
sorted=126031
SCT MATCH, addr->name MATCH, name->addr MATCH
```

The full source is at
[https://github.com/Dere3046/ksymless_Android](https://github.com/Dere3046/ksymless_Android).
