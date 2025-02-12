Hello there!

Welcome everyone! Let's get started.

Now first things first,  my name is Patrick Pichler and  I am currently employed
at Cast.AI as a staff engineer, developing a Kubernetes security product.

Originally I  started my  career as  a Java  Software Developer,  but everything
changed when I stumbled upon Linux and the cloud. This definitely transformed me
into a  full-on Linux  nerd.

At my day job, I am part of the Kubernetes Runtime Security team. We develop an
agent, that can detect anomalous  behavior in your workloads, called kvisor.

As with all the things nowadays, it is using eBPF.

Who of you here has heard about BTF before?

As we all know eBPF is pretty  powerful. You for sure have used `bpftool` before
to dump  the content of  a BPF  map. Did you  ever wonder how  exactly `bpftool`
knows how to interpret  the data in the map and how to  transform them it into
something human readable?  This is where BTF  comes in. BTF stands  for BPF Type
Format and adds the missing piece of introspection to eBPF.

Typically such  metadata is represented via  the DWARF format. DWARF  is used by
many compilers. One  of the biggest problems with DWARF  is its verbosity. DWARF
is rather generic,  since it has to support  a lot of complex use  cases. Only a
subset of DWARFs features are required by the Linux  Kernel though. Additionally,
DWARF generates the debug metadata for each compilation unit. In C/CPP this is a
single file. This means it will generate the debug information of any referenced
type down  to the primitives for  each C/CPP file. The  linker then concatenates
all the  related debug data  and puts it into  the `.debug_info` section  of the
resulting ELF binary. For a generic Linux kernel build, the debug data alone can
easily take up more  than `120MB`. As you can see DWARF,  while powerful, is not
the optimal format to get introspection into kernel types.

Out of this need, BTF was created. The first mention of BTF I can find was in
[this](https://lore.kernel.org/lkml/94a4761f-1b51-8b70-fb7f-3cea91c69717@fb.com/)
message on the LKML back in November 2017. In this thread, Alexeii mentions that
BTF was discussed  at the 2017 Linux  Plumber Conference and links to  a post on
LWN. The referenced talk  in the post by Martin Lau is  more concerned with only
creating a type format  to represent the data in BPF maps.  The LWN article even
expresses some  doubt, that  the idea  will get  far, which  is rather  funny in
retrospect.

BTF is heavily inspired  by Sun's Compact Type Format, which  is used for kernel
debug symbols  in Solaris since version  9. As pointed out  before, the original
goal for BTF  was to describe data in  eBPF maps, but nowadays it is  used for a
lot  more.  This ranges  from  function  type definition  to  even  down to  the
source/line information.

Let's dive into the nitty gritty details of  how BTF looks like. Here we can see
BTF in its raw  binary blob form. The beginning of the BTF  blob is specified by
the `btf_header` struct. The magic is  always `0xEB9F`. The encoding for big and
little endian system will  differ though, which can be used  to test what target
BTF was generated for. The header is designed with extensibility in mind, as the
`hdr_len` field will always be set  to the value of `sizeof(struct btf_header)`.
We can also see that BTF consists of two sections, namely `type` and `string`.

The `string`  section is a list  of `NULL` terminated strings,  where the first
value in the list, must be a `NULL`  string, which means it has a length of `0`.
All other strings are the simply appended.

The `type` section is a bit more complicated. Like the `string` section, it is a
list  of  values.  All  values  consist of  two  parts,  the  `struct  btf_type`
definition and then a type specific trailing section. We start by looking at the
`struct btf_type`. The first field we see  is the `name_off`. To get the name of
the type, all we need to do is look at the given offset in the `string` section.
For example,  if the string  section consist of  `\0HELLO\0WORLD\0`  and the
`name_off` is `6`, the name of the type  would be `WORLD`. The `info` field is a
bitfield, which contains `vlen` as the  first `16bit`, a padding of `8bit`, then
the kind of the type in the  next `4bit`, followed by `2bit` padding and finally
a `kind_flag`.

The  value of  `kind` can  be mapped  to one  of `20`  pre-defined types.  It is
important to note, that the `type` section  encodes debug info and not just pure
types. For  example, `BTF_KIND_FUNC` represents  a defined subprogram and  not a
type. You may have  noticed that the kind definitions start  with `1`. Kind type
`0` is reserved for the `void` type.

The meaning of  `vlen` and `kind_flag` is depending on  the referenced type. For
example, if we encounter  a `kind=4` type, which is a  `STRUCT`, `vlen` tells us
how many fields the  struct has. We are simply going  to ignore the `kind_flag`.
All you need to know is, that it is used in combination with bit fields. You may
wonder where we can now find the  definition of the struct fields. This is where
the second part of the value comes into play.

Once again depending on the `kind` of the type, there is additional information
encoded into the bytes following the `struct btf_type` definition. I will not
bore you with all the potential values, so we are going to look at two examples:
`BTF_KIND_STRUCT` and `BTF_KIND_PTR`.

`BTF_KIND_PTR` defines a pointer to a certain type. In our example here the type
we are looking at is `int *`, with ID  `5`. It will come as no surprise that the
`kind` of the type will be set to  `BTF_KIND_PTR`. The BTF spec says, that a PTR
cannot have it's own name, meaning that  `name_off` will be always `0`. The same
is true for `vlen` and the `kind_flag`. For `BTF_KIND_PTR` the last field in the
`btf_type` contains the  type ID of the  underlying type of the  pointer. In the
shown example,  we point to  the type with  ID `1`, which  is `int`. As  all the
necessary information can be encoded into the `struct btf_type` header, there is
no trailing data. `BTF_KIND_PTR` is one of `8` such types without trailing data.

For `BTF_KIND_STRUCT` the  trailing data is a list of  `btf_member`. We can find
the number of members in the `vlen`  field of the `struct btf_type` `info`. Each
member encodes its name via the `name_off` field, which once again is the offset
into the strings table. The `type` field, as the name implies, contains the type
id of the field.  We can once again head back to the  type section to figure out
the definition  of the referenced  types, by looking at  the index in  the list.
`offset`  is a  special field,  that depending  if the  `kind_flag` in  the type
definition is set, has  a different meaning. All we need to know  is, that it is
used to encode bitfield  information. In case you want to  learn more, head over
to the Linux Kernel BTF docs.

The BTF definitions for the programs we  write, are created by the compiler tool
chain and stored in the `.BTF` ELF section of the resulting binary.

For the kernel, the BTF definition is produced by a tool called `pahole`. Instead
of directly producing BTF definitions, it instead takes the DWARF debug info as
an input and transforms it to BTF. You can find the resulting file under
`/sys/kernel/btf/vmlinux`. Checking the size of it, on my machine it has around
`~7MB`. This is a huge step down from the `~120MB` the DWARF debug data would
produce.

To achieve this level of size reduction,  it is not enough to just convert DWARF
to BTF  one to one,  as it will  cause a lot of  duplication. As we  have heard,
DWARF works on compilation units and will happily duplicate type definitions. To
work around  this, Andrii Nakryiko came  up with a clever  algorithm to compress
the debug information  to an acceptable level. `pahole` is  not implementing the
algorithm  itself,  but  instead  uses  the  `btf__dedup`  function  exposed  by
`libbpf`.

To better understand, why deduplciation is needed, we are goint to take alook at
a sample first. You  can find the same sample in the docs  of `btf__dedup`, so I
did not come with it on my own.

Imagine we have two compilation units, each  using the same structs `S`, `A` and
`B`. The  two compilation  units have incomplete  type information  about either
struct `A` or  `B`. In the case of  CU #1, BTF knows that `struct  B` exist, but
that is about it. The same is true for  CU #2, but here it is `struct A`. Due to
compilation unit  isolation, there  will be  no single  unit with  complete type
information describing all  three structs. This might cause a  lot of duplicated
and  redundant type  information. To  further complicate  the matter,  the graph
formed by types, does contain cycles.

The idea  of the algorithm is  to deduplicate, as  well as merge and  resolve as
much type information as possible.

To achieve this goal, the algorithm works in 7 separate passes:
 1. Strings deduplication.
 2. Primitive types deduplication (int, enum, fwd).
 3. Struct/union types deduplication.
 4. Resolve unambiguous forward declarations.
 5. Reference types deduplication (pointers, typedefs, arrays, funcs, func
    protos, and const/volatile/restrict modifiers).
 6. Types compaction.
 7. Types remapping.

In our example, the  expected outcome would be a single  BTF type that describes
structs `A`, `B` and `S`, as if  they were defined in a single compilation unit.
The same is true for any built in types, such as `int` or pointers.

We  are not  going into  more details  about  the steps  here. In  case you  are
interested, I can highly recommend checking out the implementation in libbpf.

Awesome,  we now  understand how  BTF is  represented, as  well as  how the  BTF
definitions for the linux kernel get created.  In addition to that, the BTF spec
also defines a set of kernel APIs used to work with BTF.

First, let us understand  why a kernel API is even needed. If  you think back to
BTFs original  use case of  interpreting BPF map  data, it raises  the question,
where would  the required  BTF data even  be stored. The  answer is,  inside the
kernel. The kernel API offers methods for loading and introspecting BTF types.

The overall flow is split into two parts.

The first part starts starts by some amazing application wanting to persist some
data between eBPF program runs. Of course it is going to use a BPF map for this.
Maps are  created via the `BPF_MAP_CREATE`  command in the `bpf`  syscall. If we
take a closer at the passed  attributes, we see that there are `btf_key_type_id`
and  `btf_value_type_id` fields.  As the  name  implies, they  specify the  type
information for the key  and value by referencing some type id.  As we have seen
before, BTF type  IDs are in the  end just an increasing counter,  that is valid
within a  BTF specification. We can  pass the BTF spec  via a FD in  form of the
`btf_fd`  field. The  price question  now is,  how do  we get  that BTF  spec FD
though? This  is where the `BPF_BTF_LOAD`  command comes into play.  With it, we
can pass a buffer that contains the BTF spec, as we have recently learned and we
get back  a FD  we can  use for  creating maps. So  the high  level flow  for an
application looks something  like the following: 1. Create BTF  spec buf 2. Load
BTF spec  via BPF_BTF_LOAD command  3. Create map  with referenced BTF  spec and
key/value types

Ok cool, we now have the map created, but how do tools such as `bpftool` then know
how to interpret the content?

This is the second  part of the flow supported by the kernels BTF API.

We  start by  searching for  the map  with a  given name  to dump.  This can  be
achieved  by  first  loading  the  next  ID  of  maps  in  the  kernel  via  the
`BPF_MAP_GET_NEXT_ID` command. With this ID, we can now get the corresponding FD
via `BPF_MAP_GET_FD_BY_ID`.  With the FD, we  get access to the  map details via
`BPF_OBJ_GET_INFO_BY_FD`.

The  `bpf_attr`   for  the  `BPF_OBJ_GET_INFO_BY_FD`  command   looks  like  the
following. It expects us to pass in a FD  to the object we want to load, as well
as an  `info` ptr the  kernel will use to  fill the information.  The `info_len`
tells the kernel the  size of the buffer. The structure written  to the info ptr
depends on  the underlying BPF object  the FD is  pointing to. For maps  it will
write the data as  specified by the `bpf_map_info` struct. Here  we get the name
of  the map,  which  we can  use to  test  if we  found  our target  we want  to
introspect. In addition  to that the info  also gives us the key  and value type
IDs. Those  two on their  own are not  too useful, so we  also get the  BTF spec
where those types are defined, in the  form of the `btf_id`. If the name doesn't
match, we  just go back  to call `BPF_MAP_GET_NEXT_ID`  and search for  the next
map. If we found our target map, there is  a light at the end of this tunnel, so
stay  with me.  With the  `btf_id` we  can call  `BTF_GET_FD_BY_ID`, to  get the
underlying FD for the BTF ID. All that is  left to do is to plug the FD into the
`BPF_OBJ_GET_INFO_BY_FD` call. The kernel will write  the BTF spec into a buffer
we pass to it  the form of the `btf` field in the  `bpf_btf_info` struct. We can
then parse the BTF spec and pretty print the content of a map.

The usefulness of BTF  doesn't end here though. I guess if  you have worked with
software before, it comes as no surprise that APIs will change. The same is true
for the Linux Kernel. Especially with a tool like eBPF, where we can effectively
peak into the  raw memory of the kernel to  retrieve useful information, writing
code that supports different versions of the  Linux kernel is hard. This is were
so called CO-RE comes into play.  CO-RE stands for `Compile Once Run Everywhere`
and  aims to  make eBPF  programs  portable between  different kernel  versions.
Before the  advent of  CO-RE and  BTF, achieving this  level of  portability was
close to impossible. There were some creative workarounds for it though, such as
bringing  a whole  complier tool  chain  to the  target host  and compiling  the
programs on the target host. This of course was not lightweight at all. With the
introduction of CO-RE this time is luckily behind us.

But  how does  CO-RE  work? It  all  starts with  in the  eBPF  code you  write.
`libbpf`  exposes a  special `bpf_core_read`  macro,  that will  wrap the  given
`src`  expression in  a  `__builtin_preserve_access_index`  function call.

Without  CO-RE,  the produced  eBPF  code  will  look  like the  following.  The
arguments we pass to the `bpf_probe_read` functions are stored in R1-R3, with R1
being  the first  argument. As  we can  see here,  R1 will  point to  the memory
location `start_time`  is stored. `bpf_probe_read`  expects the size to  read as
the second argument. In  this example we read a `u64`, which has  8 bytes, so R2
is set  to 8. Reading  from a struct  is just reading  at a certain  offset, the
field is  going to be. R3  will first be  initialized to the memory  address the
task  struct is  stored. Next  `1808` will  be added,  which corresponds  to the
offset of the `start_time` field within the `task_struct` in the kernel version,
this code was compile.

If  we  now  use  the  CO-RE  version  of  reading  memory,  things  get  pretty
interesting. The resulting code produced by  the compiler will look the same. It
still will produce code that will read from a certain offset in the task struct.
In addition  to that it  will emit so called  CO-RE relocations. You  might have
heard  about  ELF  relocations  before,  but  those  are  not  the  same.  CO-RE
relocations are stored within the `.BTF.ext` section of the resulting binary. At
runtime, the eBPF loader library used,  e.g. `libbpf`, `cilium/ebpf` or `aya` to
name a few,  will take this CO-RE  information and patch the  produced eBPF code
with the right offset, based on the information provided by BTF.

Let us go one step deeper now and have a closer look at what data resides in the
`.BTF.ext` section.

The start of  the section is defined via the  `struct btf_ext_header`. The first
few  fields  in the  `btf_ext_header`  are  exactly  the  same as  with  `struct
btf_header`. This means the `magic` is also set to `0xEB9F`

The  data  can  be  split  into three  sections.  `func_info`,  `line_info`  and
`core_relo`.

The data in each  of the section follow the same basic format.  In a nutshell it
is a  array of `btf_ext_info_sec`,  that is prefixed  by a `4`  byte `rec_size`.
Remember the  rec_size, we are  going to  need it in  a bit. Peeking  inside the
`struct btf_ext_info_sec` definition, we can see  that each section gets a name,
in the form  of an offset into the  strings table. In addition to  that, we will
find a field called `num_info`. The last field is in the form of a dynamic sized
array. The length of the array can now be calculated by taking the `rec_size` we
saw before, times the number stored in `num_info`.

The data  we find in the  trailing array is  defined by whatever section  we are
looking at.

As the name implies, `func_info` holds  the definitions of all functions defined
in our  eBPF program. The `insn_off`  field points to where  the function starts
and the `type_id` to a `KIND_FUNC` type in the binaries BTF spec.

`line_info` on the other hand is used to map eBPF instructions to their location
in  the source  file. This  is useful  when trying  to understand  the resulting
binary from your eBPF code. Same as with `func_info`, the `insn_off` field holds
a pointer into our instructions the  information is for. `file_name_off` is once
again an offset into  the `strings` section, that gives us the  name of the file
we can  find original line  in. `line_off` is also  a offset into  the `strings`
section  and will  give  us the  full  source code  line  the instructions  were
compiled  from. Which  is  once  again useful  for  understanding  the raw  eBPF
instructions. The last field `line_col`  encodes the line and column information
we can find the line in our source code.

Now to  the CO-RE  part of  `.BTF.ext`. It is  a bit  more complicated  than the
`func_info` and `line_info`.

As we can see, there appears to be different kinds of relocations. All that we
need to know is, that we can group those kinds into three categories.

Field-based,  which  is  used  to   patch  an  instruction  with  field  related
information, for example, the offset used in a load instruction to access the
specified field in the target kernel.

Type-based, which allow us to query type related informations. A good example of
this is testing if a certain type exists.

Enum-based, which allow us to access enum related information. For example, if
we want to test if a certain enum value exist.

We  are  not going  to  look  into the  individual  relocation  kinds in  detail
though. If  you are interested,  I can highly  recommend checking out  the `enum
bpf_core_relo_kind` in the  linux kernel. It contains pretty  useful comments to
understand what the different kinds do.

Back to `struct bpf_core_relo`. Besides the `kind`, the relocation also specifies
the `insn_off` this relocation is for. In the end, this is where the loader library
performs the patching.

The  `type_id` points  to the  type we  want  to get  a relocation  for. In  our
previous example, with reading a  field from `struct task_struct`, the `type_id`
would point to whatever the id of `task_struct` in the type definition is.

The `access_str_off` field is also pretty special. It points to a string in the
strings section, describing how to access the field within the struct. The exact
meaning is depending on the `kind` of the relocation though.

For  type-based relocations,  the string  referenced will  always be  `"0"`. For
enum-based relocations,  the string will  contain the  index of the  enum value,
within the enum type. All good, makes sense.

For field-based based though, the story is  a bit more complicated. If you think
it will just point to the name of the  field we want to load in the target type,
you are wrong.  It will point to  a value looking something like  `0:1`. I know,
this look strange at first sight, but it makes a lot of sense. Let's have a look
at an example. We are going to assume there is the following struct definition

```c
struct sample {
    int a;
    int b;
    int c;
} __attribute__((preserve_access_index))
struct sample *s;
```

The access string effectively encodes how to access fields within the struct. We
need to split the string by `:` and now we end up with a list of access indexes.
For example, to encode `s[0].a`, the  resulting string will look like `0:0`. The
first element in the  list will be the index into the  array, whereas the second
is now  the index of  the field we  want to  access. If we  have a case  such as
`a->b`, the resulting string would look like  `0:1`.

Now to put it all together.

On a high  level, this is how the  whole flow then works. The  loader will parse
the kernels BTF spec, as well as the BTF of whatever program we want to load. It
will  then go  ahead  and  parse the  `.BTF.ext`  section  containing the  CO-RE
relocations. Next it will iterate over all CO-RE instructions it finds and tries
finding a matching type in the kernel spec. This matching works by comparing the
names of the types.  If the target kernel type has been found,  it will go ahead
an use the access  info from the access string to figure  out the field offsets.
Last but  not least, the target  instruction will then be  patched with whatever
information the relocation type specifies.

We  leave  it  at  that  though  and I  would  encourage  you  to  checkout  the
implementation of your bpf library of choice.

OK awesome, but this clearly will not work with field renames. The loader will
then never find a matching string in the BTF definition of the kernel. Luckily
for us, CO-RE has us covered.

The BPF  CO-RE struct naming convention  specifies, that any string  after `___`
will  be ignored.  Andrii calls  this  the `ignore  suffix rule`  which I  think
is  a  pretty  good  name  for  it. But  what  exactly  does  this  mean?  Let's
imagine we  want to read the  `state` field of the  `task_struct`. Additionally,
we  want  to  support  any  kernel  starting from  `5.10`.  The  bad  news,  the
field  was renamed  from  `state` to  `__state` in  kernel  version `5.14`.  How
do  we  now encode  the  field  rename in  our  BTF  definition? The  answer  is
pretty simple,  we create  a copy  of the `task_struct`  definition and  call it
something  like `task_struct___before_514`.  In  our  code we  can  now use  the
`bpf_core_field_exists` helper, that allows us  to evaluate if the `task_struct`
has the field we want, or not. If  it does, we can access the field directly. If
it doesn't, we  cast the `task_struct` to  `task_struct___before_514` and access
the `state` field.

There will be three CO-RE relocations happening. One for testing if the field
exists, and the other two reading the corresponding fields. This begs the question,
what does the loader do, if we want to read an non existing field? The answer is
pretty interesting. The loader will effectively poison any CO-RE relocation it
cannot resolve. The poison it uses is the predefined `0xbad2310` constant.

In our  example it would look  like the following. If  we run our app  on kernel
version lower  than `5.14`, the loader  will patch the field  check condition to
`false`, as the `__field` does not exist.  It will patch the valid offset in the
else case, as it can find the target field. The read of the `__state` field will
be poisoned.  The verifier  is now  smart enough, to  understand that  since the
field  check always  returns false,  it  doesn't have  to check  the true  case.
Otherwise it would blow up.

On kernel version bigger  than or equal to `5.14`, it would  be reversed. So the
field check is patched to `true`, the read of `__state` is patched with whatever
offset and finally the read of `state` is poisoned.

And that  is pretty much  it with  CO-RE for today.

BTF usage within the kernel doesn't end here. We did not even touch the topic of
how `kfuncs`  use BTF and what  the verifier does with  it. There is also  a lot
to  still  discover  in  how  the different  loader  libraries  implement  CO-RE
relocations, as we only covered them on a high level. Maybe there will be part 2
of this talk in the future.

That is it for today!

I would also encourage you to  check out my personal blog at patrickpichler.dev.
Currently it  looks a  bit empty, but  I hopefully get  around to  transform all
research I  have done from past  talks into articles  and put them up  there. So
stay tuned, hopefully.

If you like to  discuss more about BTF, eBPF or pretty  much anything, feel free
to approach me.
