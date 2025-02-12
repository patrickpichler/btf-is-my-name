* First mention of BTF
    * https://lwn.net/Articles/734453/
    * https://lore.kernel.org/lkml/4acdc081-341d-ee91-a591-b1d331a8c8d5@fb.com/
    * talk notes
        > BPF Introspection with CTF
        > Since the contents of maps is custom, it's difficult to understand
        > what is in BPF maps if the source code is missing.
        > We'd like metadata, bounded to the BPF map object, for debugging.
        > We think Compact C-Type Format (CTF) is a good fit here.
        > Can be a converter of dwarf to ctf, or llvm might generate ctf.
        > The kernel can even pass the ctf back to user-space for pretty
        > printing.
        > Steven: what about having this in a debugfs directory?
        > Mathieu: why does this even need to be in the kernel? Could be a
        > process in user space to handle this information. (PeterZ agrees.)

* Currently BTF requires DWARF
    * pahole is used to transform DWARF into BTF
    * BTF can only contain information present in DWARF
    * some kernel structures cannot be represented in DWARF
    * there is work to emit BTF natively from compilers
    * native compiler support is causing issues for rust
        * rust toolchain currently does not support BTF
    * rust is also emitting DWARF constructs currently not handled by pahole
    * one examples would be rust enums
        * they do not have a stable representation
        * combiler compiler is free to optimize
    * CO-RE is also problematic from rust
    * there is no `preserve_access_index` in rust
    * the compiler can reorder fields in rust structs
    * https://lwn.net/Articles/991719/

*
