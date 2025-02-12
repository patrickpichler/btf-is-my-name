* introduction

* Why is something like BTF needed
    * BPF very powerful
    * Introspection is still missing
    * usually DWARF format is being used
        * list some downsides of DWARF
    * DWARF info is emitted for each CU, causing a lot of duplicates
    * BTF solves the problem via deduplication algorithm

* Short history of BTF
    * Rought timeline
    * Show the mailing list messages

* Technical deep dive into BTF
    * What components are there in BTF
    * How does BTF encoding work
    * Quick intro into the deduplication algorithm
    *

* CO-RE
    * what problem does it solve
    * how does it work?
        * show examples of eBPF programs
        * show how the loader replaced CO-RE relocs
    * BTF in action

* BTF enabled BPF trace points
    * how do they compare to regular trace points
