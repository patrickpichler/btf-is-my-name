---
colorSchema: light
theme: apple-basic
highlighter: shiki
lineNumbers: false
drawings:
  persist: false
transition: none
title: BTF is my name, typing my game
mdc: true
defaults:
    layout: center
layout: center
class: text-center
---

<div class="w-full h-full flex flex-justify-end flex-items-end">
    <span class="m-b-10" style="color: #000000; text-shadow: 1px 1px #bac2de;">
        <span class="fancy-headline">
            BTF is my name
        </span>
        <br/>
        <span class="fancy-headline-small">
            Typing is my game
        </span>
    </span>
</div>

---
layout: full
---

<div class="grid grid-cols-[1fr_35%] gap-6">

<div>
<h1 class="bold">Who am I?</h1>

<br/>

<h2>Software engineer turned Cloud Enthusiast <noto-cloud /></h2>
<br/>
<h2>Kubernetes wizard <noto-magic-wand /></h2>
<br/>
<h2>Linux Nerd <devicon-linux /></h2>
</div>

<div>
<img src="/profile_pic_compressed.jpg" style="border-radius: 50%;"/>
</div>

</div>

<!--
Originally I started my career as a Java Software Developer, but everything changed when I stumbled
upon Linux and the cloud. This definitely transformed me into a full-on Linux nerd. Do not question the MacBook though.
-->

---
layout: image
image: /ebpf_so_hot_meme.png
backgroundSize: 50%
---
---
layout: fact
---

<span>
    Who has heard about BTF before?
</span>

<!--
* eBPF is pretty powerful
* you may have used `bpftool` before to dump content of a map
-->

---
layout: section
class: code-fill
---

```shellsession
$ sudo bpftool map dump name data
[{
    "key": 3,
    "value": {
        "comm": "bash"
    }
},{
    "key": 17,
    "value": {
        "comm": "cat"
    }
}]
```

<!--
* have you ever wondered how bpftool knows how to interpret map data
* how does it transform it into something human readable
* this is where BTF comes in
-->

---
layout: fact
---

<span>
    BTF = BPF Type Format
</span>

<!--
* btf stands for BPF type format and adds missing piece of introspection to eBPF
-->

---
layout: fact
---

<span>
    DWARF
</span>

<!--
* typically such metadata is represented in DWARF format
* DWARF is used by many compilers
* one of biggest issues is its verbosity
* rather generic, since it supports lot of use cases
* linux kernel doesn't need most of the features
* additionally, DWARF produces debug info per compilation unit
-->

---
layout: image
image: /dwarf.excalidraw.svg
backgroundSize: contain
---

<!--
* in c/cpp a compilation unit is usually a file
* DWARF will generate debug info by any referenced types down to primitives for each c/cpp file
* linker concats all the debug data and puts it into the `.debug_info` section of the resutling binary
* for generic linux build, debug data can take up to 120MB
* DWARF is powerful, but not optimal for getting introspection into kernel types
* out of this need, BTF was created
-->

---
layout: section
class: code-fill
---

<span class="code-small-font">

```git-commit {|12-13,15-17}
From: Alexei Starovoitov <ast@fb.com>
To: Sandipan Das <sandipan@linux.vnet.ibm.com>, <netdev@vger.kernel.org>
Subject: Re: [RFC PATCH] bpf: Add helpers to read useful task_struct members
Date: Sat, 4 Nov 2017 18:34:27 +0900  [thread overview]
Message-ID: <94a4761f-1b51-8b70-fb7f-3cea91c69717@fb.com> (raw)

I don't think it's a solution.
Tracing scripts read other fields too.
Making it work for these 3 fields is a drop in a bucket.
If randomization is used I think we have to accept
that existing bpf scripts won't be usable.
Long term solution is to support 'BPF Type Format' or BTF
(which is old C-Type Format) for kernel data structures,
...
There will be a tool that will take dwarf from vmlinux and
compress it into BTF. Kernel will also be able to verify
that BTF is a valid BTF.
...

```

</span>

<div class="attribution">
    <a href="https://lore.kernel.org/lkml/94a4761f-1b51-8b70-fb7f-3cea91c69717@fb.com/">LKML thread</a>
</div>

<!--
* the first mention of BTF i can find is this LKML entry from 2017
* alexei mentions BTF was discussed at the Linux Plumbers conference that year
* it also links a post on LWN
-->

---
layout: image
image: /lwn_btf.png
backgroundSize: 90%
---

<!--
* the referenced talk by Martin Lau is more concerned with only creating a type format to represent ebpf map data
* lwn article even expresses doubt that the idea will get far
* rather funny in retrospect
-->

---
layout: fact
---

<span>
    Heavily inspired by<br/> Sun's Compact Type Format
</span>

<!--
* btf took heavy inspiration from sun CTF
* CTF is used for kernel debug symbols since solaris version 9
* original goal for BTF was map introspection, but nowadays there are more use cases
-->

---
layout: section
---

<div class="text-size-4xl">

* Describe BTF map data
* Function type definitions
* Relocatations
* Line information
* ...

</div>

<!--
* this ranges from function type defs, down to source/line info
* let's dive in
-->

---
layout: image
image: /dive_in.jpg
---

<div class="attribution">
    <a href="https://www.freepik.com/free-photo/portrait-young-shirtless-guy-wearing-snorkel-goggles_8073819.htm#fromView=search&page=1&position=43&uuid=6343b1ac-c27b-4800-abf2-6b6e07e90b0d&query=dive">Image by drobotdean on Freepik</a>
</div>

<!--
* BTF is always represented as data blob
-->

---
layout: image
image: /btf_bin.png
backgroundSize: 90%
---

<!--
* here we can see BTF in its raw binary blob form
* the first few bytes of the blob are specified by the `btf_header` struct
-->

---
layout: section
class: code-fill
---

```c {|1|8|11-14|13-14}
#define BTF_MAGIC   0xeB9F
#define BTF_VERSION 1

struct btf_header {
    __u16   magic;
    __u8    version;
    __u8    flags;
    __u32   hdr_len;

    /* All offsets are in bytes relative to the end of this header */
    __u32   type_off;   /* offset of type section   */
    __u32   type_len;   /* length of type section   */
    __u32   str_off;    /* offset of string section */
    __u32   str_len;    /* length of string section */
};
```

<!--
* magic always has to be 0xeB9F
* encoding for big/little endian system will differ, which ca be used to test the target btf was created for
* header is designed with extensibility in mind
* `hdr_len` always set to `sizeof(btf_header)`
* btf defines two sections: `types`/`strings`
-->

---
layout: image
image: /btf_strings.png
backgroundSize: 90%
---

<!--
* string section is a list of NULL terminated strings
-->

---
layout: image
image: /btf_strings.excalidraw.svg
backgroundSize: contain
---

<!--
* first value in the string section must be a NULL string, which means it has a length of 0
* all other strings are simply appended
-->

---
layout: section
class: code-fill
---

```c {11-12}
#define BTF_MAGIC   0xeB9F
#define BTF_VERSION 1

struct btf_header {
    __u16   magic;
    __u8    version;
    __u8    flags;
    __u32   hdr_len;

    /* All offsets are in bytes relative to the end of this header */
    __u32   type_off;   /* offset of type section   */
    __u32   type_len;   /* length of type section   */
    __u32   str_off;    /* offset of string section */
    __u32   str_len;    /* length of string section */
};
```

<!--
* type section is a little bit more complicated though
-->

---
layout: image
image: /btf_types_section.excalidraw.svg
backgroundSize: contain
---

<v-switch>

<template #1>
    <Arrow x1="320" y1="180" x2="420" y2="180" color="red" />
</template>

<template #2>
    <Arrow x1="320" y1="240" x2="420" y2="240" color="red" />
</template>

</v-switch>

<!--
* like strings section it is a list of values
* all values consists of two parts, `struct btf_type` definition + a type specific trailing section
* we start by looking at `struct btf_type`
-->

---
layout: section
---

```c {|2}
struct btf_type {
    __u32 name_off;
    __u32 info;

    union {
        __u32 size;
        __u32 type;
    };
};
```

<!--
* first field we see is `name_off`
* to get the name of the type, just look at the offset specified in the strings section
*
-->

---
layout: image
image: /btf_types_section_strings.excalidraw.svg
backgroundSize: contain
---

<!--
* for example, if we have a type with `name_off` `0x30`, the name would be `data` in our case
-->

---
layout: section
---

```c {3}
struct btf_type {
    __u32 name_off;
    __u32 info;

    union {
        __u32 size;
        __u32 type;
    };
};
```

<!--
* the info field is a bitfield
-->

---
layout: image
image: /btf_types_section_info.excalidraw.svg
backgroundSize: contain
---

<v-switch>

<template #1>
    <Arrow x1="150" y1="500" x2="150" y2="390" color="red" />
</template>

<template #2>
    <Arrow x1="320" y1="500" x2="320" y2="390" color="red" />
</template>

<template #3>
    <Arrow x1="485" y1="500" x2="485" y2="390" color="red" />
</template>

<template #4>
    <Arrow x1="655" y1="500" x2="655" y2="390" color="red" />
</template>

<template #5>
    <Arrow x1="820" y1="500" x2="820" y2="390" color="red" />
</template>

<template #6>
    <Arrow x1="485" y1="500" x2="485" y2="390" color="red" />
</template>

</v-switch>

<!--
* it encodes `vlen` in the first `16` bits
* then `8` bit of padding
* then `kind` in the next `4` bit
* followed by `2` bit padding
* last but not least a `kind_flag`
* `kind` specifies one of 20 predefined types
-->

---
layout: section
---

<span class="code-extra-small-font">

```c
enum {
    BTF_KIND_INT        = 1,    /* Integer  */
    BTF_KIND_PTR        = 2,    /* Pointer  */
    BTF_KIND_ARRAY      = 3,    /* Array    */
    BTF_KIND_STRUCT     = 4,    /* Struct   */
    BTF_KIND_UNION      = 5,    /* Union    */
    BTF_KIND_ENUM       = 6,    /* Enumeration up to 32-bit values */
    BTF_KIND_FWD        = 7,    /* Forward  */
    BTF_KIND_TYPEDEF    = 8,    /* Typedef  */
    BTF_KIND_VOLATILE   = 9,    /* Volatile */
    BTF_KIND_CONST      = 10,   /* Const    */
    BTF_KIND_RESTRICT   = 11,   /* Restrict */
    BTF_KIND_FUNC       = 12,   /* Function */
    BTF_KIND_FUNC_PROTO = 13,   /* Function Proto  */
    BTF_KIND_VAR        = 14,   /* Variable */
    BTF_KIND_DATASEC    = 15,   /* Section  */
    BTF_KIND_FLOAT      = 16,   /* Floating point  */
    BTF_KIND_DECL_TAG   = 17,   /* Decl Tag */
    BTF_KIND_TYPE_TAG   = 18,   /* Type Tag */
    BTF_KIND_ENUM64     = 19,   /* Enumeration up to 64-bit values */
};
```

</span>

<!--
* it is important to note, type section encodes debug info and not just pure types
* e.g. `BTF_KIND_FUNC` defines a subprogram and not a type
-->

---
layout: section
---

```c {6}
enum {
    // ...
    BTF_KIND_VOLATILE   = 9,    /* Volatile */
    BTF_KIND_CONST      = 10,   /* Const    */
    BTF_KIND_RESTRICT   = 11,   /* Restrict */
    BTF_KIND_FUNC       = 12,   /* Function */
    BTF_KIND_FUNC_PROTO = 13,   /* Function Proto  */
    BTF_KIND_VAR        = 14,   /* Variable */
    // ...
};
```

---
layout: section
---

```c {2}
enum {
    BTF_KIND_INT        = 1,    /* Integer  */
    BTF_KIND_PTR        = 2,    /* Pointer  */
    BTF_KIND_ARRAY      = 3,    /* Array    */
    BTF_KIND_STRUCT     = 4,    /* Struct   */
    BTF_KIND_UNION      = 5,    /* Union    */
    BTF_KIND_ENUM       = 6,    /* Enumeration up to 32-bit values */
    BTF_KIND_FWD        = 7,    /* Forward  */
    // ...
};
```

<!--
* you may have noticed ids start with `1`, rather then `0`
* type `0` is reserved for the `void` type or any unknown type
-->

---
layout: image
image: /btf_types_section_info.excalidraw.svg
backgroundSize: contain
---

<Arrow x1="150" y1="500" x2="150" y2="390" color="red" />
<Arrow x1="820" y1="500" x2="820" y2="390" color="red" />

<!--
* the meaning of `vlen` and `kind_flag` depend on `kind`
* e.g. if `kind=4` which is struct
-->

---
layout: fact
---

<span>
    IF kind = 4 <span class="text-size-4xl">(BTF_KIND_STRUCT)</span><br/>
    vlen = num fields in struct
</span>

<!--
* `vlen` encodes number of fields in the struct
* we are going to ignore `kind_flag`
* all that you need to know, it is use din combination with bit fields
* you may wonder, where the definition of fields is
* this is where the trailing section comes into play into play
-->

---
layout: image
image: /btf_types_section.excalidraw.svg
backgroundSize: contain
---

<Arrow x1="820" y1="300" x2="625" y2="250" color="red" />

<!--
* not going to bore you and go over all potential kinds
* we are going to look at two examples
-->

---
layout: fact
---

<span>
    BTF_KIND_PTR<br/>
    BTF_KIND_STRUCT
</span>

---
layout: image
image: /btf_types_section_ptr.excalidraw.svg
backgroundSize: contain
---

<v-switch>

<template #1>
    <Arrow x1="475" y1="470" x2="615" y2="470" color="red" />
</template>

<template #2>
    <Arrow x1="580" y1="300" x2="510" y2="300" color="red" />
</template>

<template #3>
    <Arrow x1="580" y1="250" x2="510" y2="250" color="red" />
    <Arrow x1="580" y1="275" x2="510" y2="275" color="red" />
    <Arrow x1="580" y1="330" x2="510" y2="330" color="red" />
</template>

<template #4>
    <Arrow x1="580" y1="350" x2="510" y2="350" color="red" />
</template>

<template #5>
    <Arrow x1="510" y1="205" x2="615" y2="205" color="red" />
</template>


</v-switch>

<!--
* BTF_KIND_PTR defines pointer to a certain type
* in our example type we are looking at is `int *` with ID 5
* the kind field for ptrs will always be 2
* BTF spec says that a PTR cannot have its own name
* `name_off` will always be 0
* same is true for `vlen` and `kind_flag` fields
* last field in the `btf_type` contains the underlying type
* in our example it points to type with ID `1`, which is `int`
* all necessary info can be encoded into `struct btf_type`, no need for trailing data
-->

---
layout: section
---

```c
enum {
    BTF_KIND_PTR        = 2,    /* Pointer         */
    BTF_KIND_FWD        = 7,    /* Forward         */
    BTF_KIND_TYPEDEF    = 8,    /* Typedef         */
    BTF_KIND_VOLATILE   = 9,    /* Volatile        */
    BTF_KIND_CONST      = 10,   /* Const           */
    BTF_KIND_RESTRICT   = 11,   /* Restrict        */
    BTF_KIND_FUNC       = 12,   /* Function        */
    BTF_KIND_FLOAT      = 16,   /* Floating point  */
};
```

<!--
* `BTF_KIND_PTR` is one of `8` such types without trailing data
* next we look at `BTF_KIND_STRUCT`
-->

---
layout: image
image: /btf_types_section_struct.excalidraw.svg
backgroundSize: contain
---

<v-switch>

<template #1>
    <Arrow x1="960" y1="240" x2="810" y2="240" color="red" />
</template>

<template #2>
    <Arrow x1="390" y1="275" x2="310" y2="275" color="red" />
</template>

<template #3>
    <Arrow x1="975" y1="272" x2="840" y2="272" color="red" />
    <Arrow x1="975" y1="340" x2="840" y2="340" color="red" />
</template>

<template #4>
    <Arrow x1="975" y1="296" x2="840" y2="296" color="red" />
    <Arrow x1="975" y1="363" x2="840" y2="363" color="red" />
</template>

<template #5>
    <Arrow x1="645" y1="195" x2="555" y2="195" color="red" />
    <Arrow x1="645" y1="227" x2="555" y2="227" color="red" />
</template>

<template #6>
    <Arrow x1="390" y1="320" x2="308" y2="320" color="red" />
    <Arrow x1="975" y1="317" x2="840" y2="317" color="red" />
    <Arrow x1="975" y1="385" x2="840" y2="385" color="red" />
</template>

</v-switch>

<!--
* trailing data is an array of `btf_member`
* number of members can be found in `vlen` field in the `btr_type` info struct
* each member encodes its name via `name_off`, which is once again offset into strings section
* `type` field as name implies, contains type id of the field
* we can once again head back to the type section to figure out the type of
* in our example, type of first member is `data` and for the second field it is `int`
* `offset` is a special field, that depending on the `kind_flag` in the `btf_type` info has different meaning
* all we need to know is that it is used in combination with encoding bitfield info
* if you want to learn more, head over to linux kernel BTF docs
-->

---
layout: fact
---

<div style="line-height: 1em">
    Compiler produces BTF definitions for your program
</div>

<!--
* BTF definitions for our programs are created by compiler tool chain
* resulting info is stored in `.BTF` section of ELF binary
-->

---
layout: section
class: code-fill code-medium-font
---

```shellsession {12}
Sections:
Idx Name                                  Size     VMA              Type
  0                                       00000000 0000000000000000
  1 .strtab                               000000f0 0000000000000000
  2 .text                                 00000000 0000000000000000 TEXT
  3 tracepoint/raw_syscalls/sys_enter     000001e0 0000000000000000 TEXT
  4 .reltracepoint/raw_syscalls/sys_enter 00000030 0000000000000000
  5 license                               0000000d 0000000000000000 DATA
  6 .rodata                               00000014 0000000000000000 DATA
  7 .maps                                 00000030 0000000000000000 DATA
  8 .bss                                  00000008 0000000000000000 BSS
  9 .BTF                                  0000f1e0 0000000000000000
 10 .rel.BTF                              00000060 0000000000000000
 11 .BTF.ext                              000001cc 0000000000000000
 12 .rel.BTF.ext                          00000190 0000000000000000
 13 .llvm_addrsig                         00000006 0000000000000000
 14 .symtab                               00000108 0000000000000000
```

<!--
* for kernel, BTF definitions are produced by a tool called `pahole`
-->

---
layout: image
image: /dwarf_to_btf.excalidraw.svg
backgroundSize: contain
---

<Arrow x1="700" y1="10" x2="700" y2="110" color="red" />

<!--
* it takes DWARF debug info as an input and transforms it to BTF
* resulting file can be found under `/sys/kernel/btf/vmlinux`
-->

---
layout: section
class: code-fill
---

```shellsession
$ ls -alh /sys/kernel/btf/vmlinux
-r--r--r-- 1 root root 6.9M Feb  9 16:23 /sys/kernel/btf/vmlinux
```

<!--
* on my machine the file has around `7MB`
* huge step down from the `120MB` DWARF debug data would produce
-->

---
layout: fact
---

1:1 DWARF to BTF not enough

<!--
* to acheive this level of size reduction, it is not enough to just convert DWARF to BTF one to one
* DWARF works on CU and will happy duplicate type definitions
-->

---
layout: fact
---

Deduplication needed

<!--
* luckily for us
-->

---
layout: fact
---

Andrii Nakryiko

<div class="attribution">
    <a href="https://nakryiko.com/posts/btf-dedup/">Andrii's Blog Post</a>
</div>

<!--
* came up with a clever algorithm to compress the debug info to acceptable level
* `pahole` not implementing the algo itself, but uses `btf_dedup` from `libbpf`
-->

---
layout: fact
---

<span>

Dedup is implemented in `btf__dedup`

</span>

<span>

    in libbpf

</span>

<!--
* to better understand why this is needed, let us have look at concrete example
-->

---
layout: section
---

<div class="grid grid-cols-[50%_50%] gap-6">

```c
/* CU #1: */

struct S;

struct A {
    int a;
    struct A* self;
    struct S* parent;
};

struct B;

struct S {
    struct A* a_ptr;
    struct B* b_ptr;
};
```

```c
/* CU #2: */

struct S;

struct A;

struct B {
    int b;
    struct B* self;
    struct S* parent;
};

struct S {
    struct A* a_ptr;
    struct B* b_ptr;
};
```

</div>

<!--
* you can find same sample in the libbpf `bpf__dedup` docs, so I did not come up with it on my own
* imagine we have two CU
-->

---
layout: image
image: /btf_dedup_sample.excalidraw.svg
backgroundSize: contain
---

<v-switch>

<template #1>
    <Arrow x1="380" y1="480" x2="380" y2="380" color="red" />
</template>

<template #2>
    <Arrow x1="560" y1="480" x2="560" y2="380" color="red" />
</template>

<template #3>
    <Arrow x1="380" y1="385" x2="380" y2="485" color="red" />
    <Arrow x1="560" y1="385" x2="560" y2="485" color="red" />
    <Arrow x1="380" y1="185" x2="380" y2="270" color="red" />
    <Arrow x1="560" y1="185" x2="560" y2="270" color="red" />
    <Arrow x1="210" y1="185" x2="210" y2="270" color="red" />
    <Arrow x1="730" y1="185" x2="730" y2="270" color="red" />
    <Arrow x1="450" y1="150" x2="350" y2="170" color="red" />
    <Arrow x1="480" y1="150" x2="580" y2="170" color="red" />
    <Arrow x1="450" y1="100" x2="350" y2="100" color="red" />
    <Arrow x1="480" y1="100" x2="580" y2="100" color="red" />
</template>

<template #4>
    <Arrow x1="370" y1="410" x2="270" y2="410" color="red" />
    <Arrow x1="370" y1="427" x2="270" y2="427" color="red" />
    <Arrow x1="560" y1="410" x2="660" y2="410" color="red" />
    <Arrow x1="560" y1="427" x2="660" y2="427" color="red" />
</template>

</v-switch>

<!--
* each using same structs `S`, `A` and `B`
* CU#1 BTF knows `B` exists, but nothing more
* same for CU#2, but with struct `A`
* due to CU isolation, there will be no single unit with complete type info, describing all three structs
* this will cause lot of duplicated and redundant type info
* to further complicate, the type graph does contain cycles
* the idea of the dedup algo is to dedup, as well as merge and resolve as much type info as possible
-->

---
layout: fact
---

<div style="line-height: 1em">
    <span class="text-size-6xl">
        Deduplication algorithm<br/>
    </span>
    <span class="text-size-4xl">
        (7 steps)
    </span>
</div>

<!--
* dedup algo works in 7 separate passes
* we only quickly glimpse at them
-->

---
layout: section
---

## Step 1

<span class="text-size-5xl">
    Strings deduplication
</span>

<!--
* no duplicated strings in strings section
-->

---
layout: section
---

## Step 2

<span class="text-size-5xl">
    Primitive types deduplication
</span>

---
layout: section
---

## Step 3

<span class="text-size-5xl">
    Struct/union types deduplication
</span>

---
layout: section
---

## Step 4

<span class="text-size-5xl" style="line-height: 1em">
    Resolve unambiguous forward declarations
</span>

---
layout: section
---

## Step 5

<span class="text-size-5xl" style="line-height: 1em">
    Reference types deduplication (ptrs, arrays, funcs, ...)
</span>

---
layout: section
---

## Step 6

<span class="text-size-5xl" style="line-height: 1em">
    Types compaction
</span>

---
layout: section
---

## Step 7

<span class="text-size-5xl" style="line-height: 1em">
    Types remapping
</span>

---
layout: image
image: /btf_dedup_sample_dedup.excalidraw.svg
backgroundSize: contain
---

<!--
* in our example the expected outcome would be single BTF spec that describes structs `A`, `B` and `S`, as if they were defined in a single CU
* same is true for any built in types, such as `int` or ptrs
* we are not going into any more details about steps here
* in case you want to learn more, check out implementation in libbpf
-->

---
layout: image
image: /hurray.jpg
backgroundSize: contain
---

<div class="attribution">
    <a href="https://www.freepik.com/free-photo/overjoyed-two-woman-ans-man-raise-fists-with-triumph-have-successful-deal_13759432.htm#fromView=search&page=1&position=5&uuid=283ecc70-a02b-4b95-acea-738b11cbf6a5&query=hurray">Image by wayhomestudio on Freepik</a>
</div>

<!--
* awesome, we now understand how BTF is represented, as well how BTF definitions are getting created
* in addition BTF spec also defines a set of kernel APIs
* first let us understand, why kernel API is even needed
-->

---
layout: section
class: code-fill
---

```shellsession
$ sudo bpftool map dump name data
[{
    "key": 3,
    "value": {
        "comm": "bash"
    }
},{
    "key": 17,
    "value": {
        "comm": "cat"
    }
}]
```

<!--
* if we think back at the original use case of interpereting BPF map data
* where would the required BTF data even be stored
-->

---
layout: fact
---

BTF is stored inside the kernel

<!--
* the answer is in the linux kernel
* the kernel API offers method for loading and introspecitng BTF types
* the overall flow is split into two types
-->

---
layout: image
image: /kernel_api_sample_prog.excalidraw.svg
backgroundSize: contain
---

<!--
* the first part starts by some amazing application wanting to persist some data using BPF maps
-->

---
layout: section
class: code-fill
---

```c {|4}
int bpf(int cmd, union bpf_attr *attr, unsigned int size);

enum bpf_cmd {
    BPF_MAP_CREATE,
    BPF_MAP_LOOKUP_ELEM,
    BPF_MAP_UPDATE_ELEM,
    BPF_MAP_DELETE_ELEM,
    BPF_MAP_GET_NEXT_KEY,
    // ...
}
```

<!--
* maps are created using the `BPF_MAP_CREATE` command in the `bpf` syscall
* if we take a closer look at the passed `bpf_attr`
-->

---
layout: section
class: code-fill
---

```c {|10-11}
union bpf_attr {
    struct { /* anonymous struct used by BPF_MAP_CREATE command */
        __u32 map_type;
        __u32 key_size;
        __u32 value_size;
        __u32 max_entries;
        // ...
        char  map_name[BPF_OBJ_NAME_LEN];
        __u32 btf_fd;
        __u32 btf_key_type_id;
        __u32 btf_value_type_id;
        // ...
    };
    // ...
};
```

<!--
* we can see that there are `btf_key_type_id`/`btf_value_type_id` fields
* as name implies, they specify the type ids of key/value by referencing some type
-->

---
layout: fact
---

<div style="line-height: 1em">
    Type ID is an increasing counter in the BTF spec
</div>

<!--
* as we have learned, BTF type IDs are in the end just some increasing counter valid within a BTF spec
-->

---
layout: section
class: code-fill
---

```c {10}
union bpf_attr {
    // ...
    struct { /* anonymous struct used by BPF_MAP_CREATE command */
        __u32 map_type;
        __u32 key_size;
        __u32 value_size;
        __u32 max_entries;
        // ...
        char  map_name[BPF_OBJ_NAME_LEN];
        __u32 btf_fd;
        __u32 btf_key_type_id;
        __u32 btf_value_type_id;
        // ...
    };
    // ...
};
```

<!--
* we can pass BTF spec via `btf_fd` field
* the price question is now, how do we get the `BTF` FD?
-->

---
layout: fact
---

How do we get the BTF FD?

<!--
* this is where the `BPF_BTF_LOAD` command comes into play
-->

---
layout: section
class: code-fill
---

```c {10}
enum bpf_cmd {
    BPF_MAP_CREATE,
    // ...
    BPF_PROG_GET_NEXT_ID,
    BPF_MAP_GET_NEXT_ID,
    BPF_PROG_GET_FD_BY_ID,
    BPF_MAP_GET_FD_BY_ID,
    BPF_OBJ_GET_INFO_BY_FD,
    // ...
    BPF_BTF_LOAD,
    BPF_BTF_GET_FD_BY_ID,
    // ...
    BPF_BTF_GET_NEXT_ID,
    // ...
};
```

---
layout: section
class: code-fill
---

```c {|4}
union bpf_attr {
    // ...
    struct { /* anonymous struct for BPF_BTF_LOAD */
        __aligned_u64 btf;
        __aligned_u64 btf_log_buf;
        __u32         btf_size;
        __u32         btf_log_size;
        __u32         btf_log_level;
        __u32         btf_log_true_size;
        __u32         btf_flags;
        //...
    };
    // ...
};
```

<!--
* with it, we can pass a buffer that contains the BTF spec and we get back a FD via the return value
-->

---
layout: section
---

```c {|1|3-5|7-11}
void *btf_spec = load_btf_spec(); // However this is done

int btf_fd = bpf(BPF_BTF_LOAD, {
        .btf = btf_spec,
    }, /*..*/);

int map_fd = bpf(BPF_MAP_CREATE, {
        .btf_fd   = btf_fd,
        .key_id   = 4,
        .value_id = 6,
    }, /*..*/);
```

<!--
* the high level flow looks something like this
* create the BTF spec buffer
* load it into the kernel via `BPF_BTF_LOAD`
* create a map with the referenced BTF spec and key/value types
* ok cool, how do tools such as `bpftool` then know how to inperpret the content
-->

---
layout: image
image: /kernel_api_introspection.excalidraw.svg
backgroundSize: contain
---

<v-switch>

<template #1>
    <Arrow x1="70" y1="150" x2="215" y2="150" color="red" />
</template>

<template #2>
    <Arrow x1="70" y1="275" x2="215" y2="275" color="red" />
</template>

<template #3>
    <Arrow x1="70" y1="411" x2="215" y2="411" color="red" />
</template>

</v-switch>

<!--
* this is the second part of the flow supported by BTF API
* we start by searching for a map with a given name we can dump
* we can do this by getting the next ID of a map in the kernel via the `BPF_MAP_GET_NEXT_ID` command
* with the ID, we can get the corresponding `FD` via the `BPF_MAP_GET_FD_BY_ID`
* with the `FD` we get access to the map details via `BPF_OBJ_GET_INFO_BY_FD
-->

---
layout: section
---

```c {|4|6|5}
union bpf_attr {
    // ...
    struct { /* anonymous struct used by BPF_OBJ_GET_INFO_BY_FD */
        __u32           bpf_fd;
        __u32           info_len;
        __aligned_u64   info;
    } info;
    // ...
};
```

<!--
* `bpf_attr` of `BPF_OBJ_GET_INFO_BY_FD` command looks like the following
* it expects us to pass in a FD to the object we want to load
* as well as a `info` ptr to a buffer that the kernel will use to fill the info
* `info_len` tells the kernel the size of the info ptr
* the structure written to `info` buffer depends on the underlying object
-->

---
layout: section
---

```c {|8|11-12|10}
struct bpf_map_info {
    __u32 type;
    __u32 id;
    __u32 key_size;
    __u32 value_size;
    __u32 max_entries;
    __u32 map_flags;
    char  name[BPF_OBJ_NAME_LEN];
    // ...
    __u32 btf_id;
    __u32 btf_key_type_id;
    __u32 btf_value_type_id;
    // ...
} __attribute__((aligned(8)));
```

<!--
* for maps it will look as specified by the `bpf_map_info` struct
* we get the `name` of the object, we can use to filter out the maps that we want
* we also get info about key/value type IDs
* IDs on their own are useless, we also get `btf_id` to retrieve the BTF spec
-->

---
layout: image
image: /kernel_api_introspection.excalidraw.svg
backgroundSize: contain
---

<v-switch>

<template #0>
    <Arrow x1="70" y1="411" x2="215" y2="411" color="red" />
</template>

<template #1>
    <Arrow x1="950" y1="411" x2="800" y2="411" color="red" />
</template>

<template #2>
    <Arrow x1="950" y1="275" x2="800" y2="275" color="red" />
</template>

</v-switch>

<!--
* if the name does not match the map we want to dump, we need to call `BPF_MAP_GET_NEXT_ID` again, with the current maps ID and preform the same dance again
* if it does match, there is light at the end of the tunnel
* we can plug the `btf_id` we got into the `BTF_GET_FD_BY_ID` cmd
* this retrieves the corresponding FD for the ID
* we can then call `BPF_OBJ_GET_INFO_BY_ID` again with the BTF FD
-->

---
layout: section
---

```c {|2}
struct bpf_btf_info {
    __aligned_u64 btf;
    __u32 btf_size;
    __u32 id;
    __aligned_u64 name;
    __u32 name_len;
    __u32 kernel_btf;
} __attribute__((aligned(8)));
```

<!--
* the BTF spec will be written into a buffer we pass to the call in the form of `btf` field in the `bpf_btf_info` struct
-->

---
layout: image
image: /kernel_api_introspection.excalidraw.svg
backgroundSize: contain
---

<v-switch>

<template #0>
    <Arrow x1="950" y1="275" x2="800" y2="275" color="red" />
</template>

<template #1>
    <Arrow x1="950" y1="150" x2="800" y2="150" color="red" />
</template>


</v-switch>

<!--
* we can now parse BTF spec and pretty print content of map
-->

---
layout: image
image: /very_nice.jpg
---

<!--
* very nice
* usefulness of BTF doesn't end here though
* if you have worked with software before, it comes at no surprise that APIs will change
-->

---
layout: fact
---

<div style="line-height: 1em;">
    <span>
        APIs change<br/>
    </span>
    <span class="text-size-4xl">
        (especially internal struct definitions)
    </span>
</div>

<!--
* the same is true for the Linux Kernel
* especially with a tool like eBPF, where we peak into raw kernel memory to retrieve useful info
* it is very challenging to write eBPF programs that support different kernel versions
* this is where CO-RE enter the scene
-->

---
layout: section
---

## The solution

<span class="text-size-5xl">
    CO-RE
</span>

<span class="text-size-4xl">
    (Compile Once - Run Everywhere)
</span>

<!--
* CO-RE stands for Compile Once - Run Everywhere
* One of it's goal is to make eBPF program portable between different linux kernel versions
-->

---
layout: fact
---

Make eBPF programs portable

<!--
* before CO-RE this was very hard
-->

---
layout: section
---

## Life before CO-RE

<span class="text-size-5xl">
    Bring compiler tool chain to target
</span>

<!--
* there were some creative work arounds, such as bringing compiler tool chain to target host and compiling programs there
-->

---
layout: fact
---

<span class="text-size-7xl">
    Lightweight
</span>

<v-click>
    <div class="absolute top-0 bottom-0 right-0 left-0 text-align-center p-20">
        <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100" width="100%" height="100%" preserveAspectRatio="meet">
          <line x1="20" y1="20" x2="80" y2="80" stroke="red" stroke-width="10"/>
          <line x1="80" y1="20" x2="20" y2="80" stroke="red" stroke-width="10"/>
        </svg>
    </div>
</v-click>

<!--
* it will come as no surprise, that this was not lightweight at all
* luckily this times are behind us
* but how does CO-RE work?
-->

---
layout: image
image: /thinking.jpg
---

<div class="h-full color-[#000000]" style="display: flex; justify-content: end; flex-direction: row">
    <div class="h-full p-r-20" style="display: flex; justify-content: center; flex-direction: column">
        <span id="headline">
            <span class="fancy-headline-small">How does </span><br/>
            <span class="fancy-headline m-l-20">CO-RE</span><br/>
            <span class="fancy-headline-small m-l-60">work?</span>
        </span>
    </div>
</div>

<!--
* it all starts with the code we write
-->

---
layout: section
class: code-fill
---

```c {|5}
// ...
struct task_struct *t = (void *)bpf_get_current_task();
u64 start_time = 0;

bpf_core_read(&start_time, sizeof(start_time), t->start_time);
// ...
```

<!--
* libbpf exposes special `bpf_core_read` macros
-->

---
layout: section
class: code-fill
---

```c {|3}
#define bpf_core_read(dst, sz, src)  \
            bpf_probe_read_kernel( dst, sz, \
                      (const void *)__builtin_preserve_access_index(src))
```

<!--
* under the hood, it will call `bpf_probe_read_kernel` to read memory from the kernel address space, but wraps the `src` in a special `__builtin_preserve_access_index` function call
-->

---
layout: full
---

<div class="grid grid-cols-[60%_1fr] gap-1 h-full">

<div class="code-fill">

```c {|7-9}
// ...
struct task_struct *t =
    (void *)bpf_get_current_task();

u64 start_time = 0;

bpf_probe_read_kernel(&start_time,
                      sizeof(start_time),
                      t->start_time);
// ...
```

</div>

<div class="code-fill">

```asm {|9-13|11,12|13|9,10}
call bpf_get_current_task
r1 = r0
r1 <<= 32
r1 s>>= 32
*(u64 *)(r10 - 16) = r1
r1 = 0
*(u64 *)(r10 - 32) = r1
*(u64 *)(r10 - 24) = r1
r3 = *(u64 *)(r10 - 16)
r3 += 1808
r1 = r10
r1 += -24
r2 = 8
call bpf_probe_read_kernel
```

</div>
</div>

<v-click>

  <Arrow x1="685" y1="500" x2="685" y2="345" color="red" />

  <div class="absolute top-315px left-655px w-60px h-25px">
    <svg viewBox="0 0 100 100" width="100%" height="100%" preserveAspectRatio="none">
      <rect
        width="100"
        height="100"
        fill="none"
        stroke="red"
        stroke-width="4"
        vector-effect="non-scaling-stroke"
      />
    </svg>
  </div>

</v-click>

<!--
* without CO-RE, the produced eBPF code will look like the following
* in eBPF arguments passed to functions are stored in R1-R5
* `bpf_probe_read_kernel` expects three arguments
* the first argument in `R1` will be the stack offset of the `start_time` variable
* since we read `u64` in this example, the size we pass as the second argument will be set to `8`
* reading a field in a struct, is just reading the data at a certain offset of the structs base pointer
* `R3` will be initialized to the memory address of `bpf_get_current_task`
* next `1808` will be added
-->

---
layout: image
image: /probe_read_struct_offset.excalidraw.svg
backgroundSize: contain
---

<v-click>
  <Arrow x1="100" y1="320" x2="290" y2="320" color="red" />
</v-click>

<!--
* this corresponds to the offset of the `start_time` field within the `task_struct` in the kernel version this code was compiled for
-->

---
layout: full
---

<div class="grid grid-cols-[60%_1fr] gap-1 h-full">

<div class="code-fill">

```c
// ...
struct task_struct *t =
    (void *)bpf_get_current_task();

u64 start_time = 0;

bpf_core_read(&start_time,
              sizeof(start_time),
              t->start_time);
// ...
```

</div>

<div class="code-fill">

```asm
call bpf_get_current_task
r1 = r0
r1 <<= 32
r1 s>>= 32
*(u64 *)(r10 - 16) = r1
r1 = 0
*(u64 *)(r10 - 32) = r1
*(u64 *)(r10 - 24) = r1
r3 = *(u64 *)(r10 - 16)
r3 += 1808
r1 = r10
r1 += -24
r2 = 8
call bpf_probe_read_kernel
```

</div>
</div>

<!--
* if we now use the CO-RE version of reading memory, things get pretty interesting
* the resulting code produced by the compiler will look the same
* it still will read from a certain offset in the `task_struct`
* in addition, compiler will also emit so called CO-RE relocations
-->

---
layout: fact
---

CO-RE will emit relocations

<!--
* you might have heared about ELF relocations before
-->

---
layout: fact
---

CO-RE relocations != ELF relocations

<!--
* it is worth noting that CO-RE relocations != ELF relocs
-->

---
layout: section
class: code-fill code-medium-font
---

```shellsession {|14}
Sections:
Idx Name                                  Size     VMA              Type
  0                                       00000000 0000000000000000
  1 .strtab                               000000f0 0000000000000000
  2 .text                                 00000000 0000000000000000 TEXT
  3 tracepoint/raw_syscalls/sys_enter     000001e0 0000000000000000 TEXT
  4 .reltracepoint/raw_syscalls/sys_enter 00000030 0000000000000000
  5 license                               0000000d 0000000000000000 DATA
  6 .rodata                               00000014 0000000000000000 DATA
  7 .maps                                 00000030 0000000000000000 DATA
  8 .bss                                  00000008 0000000000000000 BSS
  9 .BTF                                  0000f1e0 0000000000000000
 10 .rel.BTF                              00000060 0000000000000000
 11 .BTF.ext                              000001cc 0000000000000000
 12 .rel.BTF.ext                          00000190 0000000000000000
 13 .llvm_addrsig                         00000006 0000000000000000
 14 .symtab                               00000108 0000000000000000
```

<!--
* CO-RE relocations are stored in the `.BTF.ext` section in the resulting binary
* at runtime the ebpf loader lib like `libbpf`, `cilium/ebpf` or `aya` to name a few, will take CO-RE info and patch produced eBPF code with right offset, based on info probided by BTF
* let us go one step deeper and have a closer look at what data resides in the `.BTF.ext` section
-->

---
layout: section
class: code-fill
---

```c {|2-5|8-9|10-11|14-15}
struct btf_ext_header {
  __u16 magic;
  __u8  version;
  __u8  flags;
  __u32 hdr_len;

  /* All offsets are in bytes relative to the end of this header */
  __u32 func_info_off;
  __u32 func_info_len;
  __u32 line_info_off;
  __u32 line_info_len;

  /* optional part of .BTF.ext header */
  __u32 core_relo_off;
  __u32 core_relo_len;
};
```

<!--
* the start of the section is defined via the `structure btf_ext_header`
* first few fields in the `btf_ext_header` are exactly the same as in `btf_header`
* magic is also set to `0xeB9F`
* data can be split into three sections
* func_info
* line_info
* co-re relocations
* each of the sections follow the same format
-->

---
layout: section
class: code-fill
---

```git-commit {|2-5|1}
u32 rec_size;
btf_ext_info_sec sec1;
btf_ext_info_sec sec2;
...
btf_ext_info_sec secN;
```

<!--
* in a nutshell, it is an array of `btf_ext_info_sec`, that is prefixed by a `4` byte `rec_size` number
* keep `rec_size` in mind, we are going to need it in a bit
-->

---
layout: section
class: code-fill
---

```c {|2|3|4-5}
struct btf_ext_info_sec {
  __u32 sec_name_off;
  __u32 num_info;
  /* Followed by num_info * record_size number of bytes */
  __u8  data[];
};
```

<!--
* peeking inside `btf_ext_info_sec` definition, we can see that each section gets a name in the for of an offset into the strings table, stored in `sec_name_off`
* in addition, we find a field called `num_info`.
* last field is a dynamic length array
* length of the array can be calculated by `num_info` * `rec_size` we saw before
* the data in the trailing arrays is defined by whatever section we are looking at
-->

---
layout: section
class: code-fill
---

```c {|2-3|5-6}
struct bpf_func_info {
  // offset where the function starts
  __u32 insn_off;

  // KIND_FUNC BTF type that describes the function
  __u32 type_id;
};
```

<!--
* as the name implies `func_info` holds definitions of all functions defined in our eBPF program
* `ins_off` gives us the instruction offset the function starts
* `type_id` points to a `KIND_FUNC` type in the BTF spec
-->

---
layout: section
class: code-fill
---

```c {|2-3|5-6|8-9|11-12}
struct bpf_line_info {
  // offset of the instruction this info is for
  __u32 insn_off;

  // offset of the file name in the string section
  __u32 file_name_off;

  // offset of the source line in the string section
  __u32 line_off;

  // line/column information of line in source file
  __u32 line_col;
};
```

<!--
* `line_info` on the other hand is used to map eBPF instructions to their location in the source file
* this is useful when trying to understand the resulting binary from your eBPF code
* as with `func_info`, the `insn_off` field contains the offset of the instruction the line info is for
* `file_name_off` is once again an offset into the `strings` section, to give us the name of the file the line originates in
* `line_off` is also an offset into the `strings` section and will give us the full source code line the instructions were compiled from
* last, but not least, `line_col` encodes the line and column information the instruction represents in the referenced source file
* now to the CO-RE part of `.BTF.ext`
-->

---
layout: section
class: code-fill
---

```c {|11-12}
struct bpf_core_relo {
  // offset of the instruction to patch
  __u32 insn_off;

  // target type of the relocation
  __u32 type_id;

  // relocation access string (points to string in strings section)
  __u32 access_str_off;

  // kind of relocation (see `enum bpf_core_relo_kind`)
  enum bpf_core_relo_kind kind;
};
```

<!--
* it is a bit more complicated than `func_info` and `line_info`
* as we can see, there appears to be different kind of relocations
-->

---
layout: fact
---

Three types of relocations

<!--
* all that we need to know is, that we can group those kinds into three categories
-->

---
layout: section
---

## Type 1

<span class="text-size-5xl">
    Field-based
</span>

<span class="text-size-3xl">
    (e.g. patch field offset)
</span>

<!--
* first kind are field based relocations
* used to patch instructions with field related data, such as offsets of a field within a struct
-->

---
layout: section
---

## Type 2

<span class="text-size-5xl">
    Type-based
</span>

<span class="text-size-3xl">
    (e.g. does type exist)
</span>

<!--
* next we have type-based relocations
* they allow us to query type related information, such as does this type exist
-->

---
layout: section
---

## Type 3

<span class="text-size-5xl">
    Enum-based
</span>

<span class="text-size-3xl">
    (e.g. does enum value exist)
</span>

<!--
* finally we have enum-based relocations
* can be used to get information about enums
* example would be, does ceratin enum value exist
* we are not going to look into individual relocation kinds in detail
-->

---
layout: section
class: code-fill code-small-font
---

```c
enum bpf_core_relo_kind {
  BPF_CORE_FIELD_BYTE_OFFSET = 0,    /* field byte offset */
  BPF_CORE_FIELD_BYTE_SIZE = 1,      /* field size in bytes */
  BPF_CORE_FIELD_EXISTS = 2,         /* field existence in target kernel */
  BPF_CORE_FIELD_SIGNED = 3,         /* field signedness (0 - unsigned, 1 - signed) */
  BPF_CORE_FIELD_LSHIFT_U64 = 4,     /* bitfield-specific left bitshift */
  BPF_CORE_FIELD_RSHIFT_U64 = 5,     /* bitfield-specific right bitshift */
  BPF_CORE_TYPE_ID_LOCAL = 6,        /* type ID in local BPF object */
  BPF_CORE_TYPE_ID_TARGET = 7,       /* type ID in target kernel */
  BPF_CORE_TYPE_EXISTS = 8,          /* type existence in target kernel */
  BPF_CORE_TYPE_SIZE = 9,            /* type size in bytes */
  BPF_CORE_ENUMVAL_EXISTS = 10,      /* enum value existence in target kernel */
  BPF_CORE_ENUMVAL_VALUE = 11,       /* enum value integer value */
  BPF_CORE_TYPE_MATCHES = 12,        /* type match in target kernel */
};
```

<div class="attribution">
    Check out on <a href="https://elixir.bootlin.com/linux/v6.13.5/source/include/uapi/linux/bpf.h#L7426">Bootlin</a>
</div>

<!--
* if you are interested, I can highly recommend checking out the `enum bpf_core_relo_kind` definition in the linux kernel
* contains pretty useful comments to understand what the different kinds do
* back to `struct bpf_core_relo`
-->

---
layout: section
class: code-fill
---

```c {|2-3|5-6|8-9|8-12}
struct bpf_core_relo {
  // offset of the instruction to patch
  __u32 insn_off;

  // target type of the relocation
  __u32 type_id;

  // relocation access string (points to string in strings section)
  __u32 access_str_off;

  // kind of relocation (see `enum bpf_core_relo_kind`)
  enum bpf_core_relo_kind kind;
};
```

<!--
* besides `kind` the reloc also specifies the `insn_off` this reloc is for
* it is once again the offset of the target instruction this info is for
* in the end, this is where the loader lib performs the patching
* `type_id` points to the type we want to get a reloc for
* in our prev example we read a field from `task_struct`
* `type_id` there would point to whatever ID `task_struct` has
* `access_str_off` field is pretty special
* it points to string in the strings section, describing how to access the field within the struct
* the exact meaning is depending on `kind` though
-->

---
layout: section
---

## For Type-based relocation

<span class="text-size-5xl">
    access_str always "0" string
</span>

<!--
* for type based relocatins, the string will always be `"0"`
-->

---
layout: section
---

## For Enum-based relocation

<span class="text-size-5xl">
    string containing the index of enum within type
</span>

<span class="text-size-4xl">
  (e.g. "5")
</span>

<!--
* for enum-based it will contain the index of the enum value within the enum type
* all good makes sense
-->

---
layout: fact
---

Field-based a bit more complicated

<!--
* for field-based, the story is a bit more complicated
* if you think it will just point to the name of the field we want to load in the target type, you are wrong
* it will point to a value looking somethingl like this
-->

---
layout: section
---

## Field-based access string example

<span class="text-size-5xl">
  "0:1"
</span>

---
layout: image
image: /confused_woman.jpg
---

<div class="h-full" style="display: flex; justify-content: end; flex-direction: row">
    <div class="h-full p-r-20" style="display: flex; justify-content: start; flex-direction: column">
        <span id="headline color-[#FFF]" style="-webkit-text-stroke: 2px black">
            <span class="fancy-headline">What?</span>
        </span>
    </div>
</div>

<div class="attribution">
  <a href="https://www.freepik.com/free-photo/depressed-frustrated-woman-working-with-computer-laptop-desperate-work-isolated-white-wall-depression_14529381.htm#query=confused%20woman%20programmer&position=10&from_view=search&track=ais">Image by diana.grytsku on Freepik</a>
</div>

<!--
* i know it looks strange at first, but it makes a lot of sense
* let's have a look at an example
-->

---
layout: section
class: code-fill
---

```c
struct sample {
    int a;
    int b;
    int c;
} __attribute__((preserve_access_index));

struct sample *s;
```

<!--
* we are going to assume there is the following struct definition
* the access string encodes how to access the fields within the struct
-->

---
layout: section
class: code-fill
---

```c {|1-5|7}
s[0].a == "0:0"

s[0].b == "0:1"

s[8].c == "8:2"

s->c   == "0:2"
```

<!--
* for example to encode `s[0].a`, the resulting string will look like `0:0`
* the first element in the list will be the index into the array, whereas the second is the index of the field we want to access
* if we want to access `s[8].c`, the resulting string will be `8:2`
* if instead we want to access the `c` field of the `s` pointer though, the resulting string will be `0:2`
* `s->c` is effectively the same as `s[0].c`
* now to put it all together
-->

---
layout: image
image: /core_loader_algo.excalidraw.svg
backgroundSize: contain
---

<v-switch>

<template #1>
    <Arrow x1="80" y1="130" x2="220" y2="130" color="red" />
</template>

<template #2>
    <Arrow x1="80" y1="250" x2="220" y2="250" color="red" />
</template>

<template #3>
    <Arrow x1="80" y1="365" x2="220" y2="365" color="red" />
</template>

<template #4>
    <Arrow x1="805" y1="365" x2="665" y2="365" color="red" />
</template>

<template #5>
    <Arrow x1="805" y1="250" x2="665" y2="250" color="red" />
</template>

<template #6>
    <Arrow x1="805" y1="130" x2="665" y2="130" color="red" />
</template>

</v-switch>

<!--
* on a high level this is how the flow works
* loader will parse the kernel BTF spec, as well as BTF of whatever program we load
* loader will also parse `.BTF.ext` section containing the CO-RE relocations
* loader will iterate over all CO-RE instructions it finds and tries finding a matching type in the kernel spec
* this matching is done by matching names of types
* if kernel type has been found, loader will use access info string and figure out field offset
* last but not leaset, loader will patch the target instruction with whatever the relocation type specifies
-->

---
layout: fact
---

<div style="line-height: 1em">
  For more details,<br/>
  checkout your loader library of choice!
</div>

<!--
* we leave it at that though
* i would encourage you to checkout the implementation of your bpf lib of choice
* ok awesome, one problem though
-->

---
layout: fact
---

But how to handle field renames?

<!--
* this clearly will not work for field renames
* the loader will never find a matching string in the BTF definition of the kernel if the field gets renamed
* luckily CO-RE has us covered
-->

---
layout: section
---

## CO-RE naming convention

<span class="text-size-5xl">
    Ignore suffix after ___
</span>

<!--
* BPF CO-RE has this naming convention that any string after `___` will be ignored
* Andrii calls this the `ignore suffix rule`, which I think is a pretty good name for it
* but what exactly does this mean
* let's imagine we want to read the `state` field of `task_struct`
-->

---
layout: section
---

<div class="grid grid-cols-[50%_50%] gap-6">

```c
/* < Kernel 5.14 */

struct task_struct {
	struct thread_info thread_info;
	unsigned int state;
	void *stack;
	refcount_t usage;
	unsigned int flags;
  // ...
};
```

```c
/* >= Kernel 5.14 */

struct task_struct {
	struct thread_info thread_info;
	unsigned int __state;
	void *stack;
	refcount_t usage;
	unsigned int flags;
  // ...
};
```

</div>

<!--
* the field was renamed in kernel version `5.14` to `__state`
-->

---
layout: section
---

<div class="grid grid-cols-[50%_50%] gap-6">

```c {5}
/* < Kernel 5.14 */

struct task_struct {
	struct thread_info thread_info;
	unsigned int state;
	void *stack;
	refcount_t usage;
	unsigned int flags;
  // ...
};
```

```c {5}
/* >= Kernel 5.14 */

struct task_struct {
	struct thread_info thread_info;
	unsigned int __state;
	void *stack;
	refcount_t usage;
	unsigned int flags;
  // ...
};
```

</div>

<!--
* our program should support all kernel versions starting from idk `5.10`
* how do we now encode the field rename in our BTF definition?
-->

---
layout: section
class: code-fill
---

```c
struct task_struct {
	u32 __state;
};

struct task_struct___before514 {
	u32 state;
};
```

<!--
* the answer is pretty simple, we create a copy of the `task_struct` definition and call it something like `task_struct___before514`
-->

---
layout: section
class: code-fill
---

```c {|4|5|7-8}
struct task_struct *t = (void *)bpf_get_current_task();
u32 state;

if(bpf_core_field_exists(t->__state)) {
  state = BPF_CORE_READ(t, __state);
} else {
  struct task_struct___before514 *t_old = (void *)t;
  state = BPF_CORE_READ(t_old, state);
}
```

<!--
* in our code we can now use the `bpf_core_field_exists` helper to check if the `__state` field has been defined on the `task_struct`
* if it hasn't we, simply fall back reading the `state` field of the `task_struct___before514`
* note that we need to explicitly cast the value here for this to work
-->

---
layout: image
image: /loader_meme.png
backgroundSize: 45%
---

<!--
* the loader will now happily go ahead and check the `task_struct` type twice for us, since `task_struct` and `task_struct___b514` are the same to it
-->

---
layout: section
class: code-fill
---

```c {4,5,8}
struct task_struct *t = (void *)bpf_get_current_task();
u32 state;

if(bpf_core_field_exists(t->__state)) {
  state = BPF_CORE_READ(t, __state);
} else {
  struct task_struct___before514 *t_old = (void *)t;
  state = BPF_CORE_READ(t_old, state);
}
```

<!--
* there will be three CO-RE relocations happneing
* one for testing if the field exists and the other two reading the corresponding fields
* this begs the questions, what does the loader do if we want to read an non existing field
* the answer is pretty interesting
-->

---
layout: fact
---

<div style="line-height: 1em">
    If loader cannot find relocation, patch with poison value<br/>

(
<span class="color-[#b6e1a5]">
    0xbad2310
</span>
)

</div>

<!--
* the loader will effecitvely poision any CO-RE relocation it cannot resolve
* it uses the `0xbad2310` constant as a poison value
*
-->

---
layout: section
class: code-fill
---

```c {|1,5-6|1,9-11|1,7-8|}
// On kernel < 5.14
struct task_struct *t = (void *)bpf_get_current_task();
u32 state;

// Loader will patch this to return false
if(bpf_core_field_exists(t->__state)) {
  // Offset to read will be batched to 0xbad2310
  state = BPF_CORE_READ(t, __state);
} else {
  struct task_struct___before514 *t_old = (void *)t;
  state = BPF_CORE_READ(t_old, state);
}
```

<!--
* in our example it would look like the following
* if we run the appon kernel version lower than `5.14`, the loader will patch the field check condition to `false`, as the `__state` field does not exist. It will patch the valid offset in the else case, as it can find the target field
* the read of the `__state` field will be poisoned
* the verifier is smart enough to understand that since the field check always returns false, to not check the `true` branch
* if it would encount the poison value, it would blow up
-->

---
layout: section
class: code-fill
---

```c {1,5-6|1,7|1,9-11}
// On kernel >= 5.14
struct task_struct *t = (void *)bpf_get_current_task();
u32 state;

// Loader will patch this to return true
if(bpf_core_field_exists(t->__state)) {
  state = BPF_CORE_READ(t, __state);
} else {
  struct task_struct___before514 *t_old = (void *)t;
  // Offset to read will be batched to 0xbad2310
  state = BPF_CORE_READ(t_old, state);
}
```

<!--
* on kernel later than `5.14`, it would be reversed
* the field check is patched to `true`, the read of `__state` is patched with whatever offset and finally the `state` read is poisoned
-->

---
layout: fact
---

That is it!

<!--
* that is pretty much it with BTF for today
-->

---
layout: section
---

## More fun to explore

<div class="text-size-5xl">

* kfuncs
* Verifier
* Deep dive loader libs

</div>

<!--
* of course BTF usage within the kernel doesn't end here
* we didn't even talk about how kfuncs use BTF or what the verifier does with it
* there is also a lot more to be discovered how the different loader libs implement CO-RE
* we only scratched the surface
-->

---
layout: fact
---

Stay tuned for part 2!

<div class="text-size-2xl">
  (maybe)
</div>

<!--
* stay tuned for part 2..... maybe
* it was a fun topic to research
* i would also highly encourage you to checkout my blog at patrickpichler.dev
-->

---
layout: fact
---

https://patrickpichler.dev

---
layout: image
image: /blog.png
backgroundSize: 80%
---
---

# Congrats, you survived!
