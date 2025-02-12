import std.string;
import std.core;
import std.io;
import * from elf as ELF;

enum BTFKind : u32 {
  INT            = 1,
  PTR            = 2,
  ARRAY          = 3,
  STRUCT         = 4,
  UNION          = 5,
  ENUM           = 6,
  FWD            = 7,
  TYPEDEF        = 8,
  VOLATILE       = 9,
  CONST          = 10,
  RESTRICT       = 11,
  FUNC           = 12,
  FUNC_PROTO     = 13,
  VAR            = 14,
  DATASEC        = 15,
  FLOAT          = 16,
  DECL_TAG       = 17,
  TYPE_TAG       = 18,
  ENUM64         = 19,
};

struct BTFKindInt {
  u32 val;
};

struct BTFKindPtr {};

struct BTFKindArray {
  BTFKind type;
  BTFKind index_type;
  u32 nelems;
};

struct BTFKindStructUnionMember {
  u32 name_off;
  BTFKind type;
  u32 offset;
};

struct BTFKindStructUnion<auto Size> {
  BTFKindStructUnionMember members[Size];
};

struct BTFKindEnumValue {
  u32 name_off;
  u32 val;
};

struct BTFKindEnum<auto Size> {
  BTFKindEnumValue values[Size];
};

struct BTFKindFwd {};

struct BTFKindTypedef {};

struct BTFKindVolatile {};

struct BTFKindConst {};

struct BTFKindRestrict {};

struct BTFKindFunc {
};

struct BTFKindFuncParam {
  u32 name_off;
  BTFKind type;
};

struct BTFKindFuncProto<auto Size> {
  BTFKindFuncParam params[Size];
};

struct BTFKindVar {
  u32 linkage;
};

struct BTFKindDataSecInfo {
  BTFKind type;
  u32 offset;
  u32 size;
};

struct BTFKindDataSec<auto Size> {
  BTFKindDataSecInfo info[Size];
};

struct BTFKindFloat {};

struct BTFKindDeclTag {
  u32 component_idx;
};

struct BTFKindTypeTag {};

struct BTFKindEnum64Value {
  u32 name_off;
  u32 val_lo32;
  u32 val_hi32;
};

struct BTFKindEnum64<auto Size> {
  BTFKindEnum64Value values[Size];
};

bitfield BTFTypeInfo {
    vlen : 16;
    padding : 8;
    BTFKind kind : 5;
    padding : 2;
    bool kind_flag : 1;
};

struct BTFType {
  u32 name_off;
  BTFTypeInfo info;

  match(info.kind) {
    (BTFKind::INT
      | BTFKind::ENUM
      | BTFKind::STRUCT
      | BTFKind::UNION
      | BTFKind::ENUM64): u32 size;

    (BTFKind::FUNC |
       BTFKind::FUNC_PROTO): u32 type;

    (_): BTFKind type;
  }

  match(info.kind) {
    (BTFKind::INT): BTFKindInt val;
    (BTFKind::PTR): BTFKindPtr val;
    (BTFKind::ARRAY): BTFKindArray val;
    (BTFKind::STRUCT | BTFKind::UNION): BTFKindStructUnion<info.vlen> val;
    (BTFKind::ENUM): BTFKindEnum<info.vlen> val;
    (BTFKind::FWD): BTFKindFwd val;
    (BTFKind::TYPEDEF): BTFKindTypedef val;
    (BTFKind::VOLATILE): BTFKindVolatile val;
    (BTFKind::CONST): BTFKindConst val;
    (BTFKind::RESTRICT): BTFKindRestrict val;
    (BTFKind::FUNC): BTFKindFunc val;
    (BTFKind::FUNC_PROTO): BTFKindFuncProto<info.vlen> val;
    (BTFKind::VAR): BTFKindVar val;
    (BTFKind::DATASEC): BTFKindDataSec<info.vlen> val;
    (BTFKind::FLOAT): BTFKindFloat val;
    (BTFKind::DECL_TAG): BTFKindDeclTag val;
    (BTFKind::TYPE_TAG): BTFKindTypeTag val;
    (BTFKind::ENUM64): BTFKindEnum64<info.vlen> val;
    (_): BTFKind type;
  }

} [[format("format_btf_type")]];

fn format_btf_type(BTFType type) {
  return type.info.kind;
};

struct BTFHeader {
  u16 magic;
  u8 version;
  u8 flags;
  u32 hdr_len;
  u32 type_off;
  u32 type_len;
  u32 str_off;
  u32 str_len;
};

struct BTF {
  u32 start = $;

  BTFHeader hdr;

  u32 type_end =  start+hdr.hdr_len+hdr.type_off+hdr.type_len;
  BTFType types[while($ < type_end)];

  u32 strings_end = start+hdr.hdr_len+hdr.str_len+hdr.str_off;

  std::string::NullString strings[while($ < strings_end)];
};

struct BTFExtHeader {
  u16 magic;
  u8 version;
  u8 flags;
  u32 hdr_len;

  u32 func_info_off;
  u32 func_info_len;
  u32 line_info_off;
  u32 line_info_len;

  u32 core_relo_off;
  u32 core_relo_len;
};

struct BTFExtInfoSec<auto RecSize> {
   u32 sec_name_off;
   u32 num_info;
   u8 data[num_info*RecSize];
};

struct BPFFuncInfo {
  u32 insn_off;
  u32 type_id;
};

struct BTFExtInfoSec_FuncInfo<auto RecSize> : BTFExtInfoSec<RecSize> {
  u32 end = addressof(data) + sizeof(data);
  BPFFuncInfo func_infos[while($<end)] @ addressof(data);
};

struct BTFFuncInfo<auto End> {
  u32 func_info_rec_size;
  BTFExtInfoSec_FuncInfo<func_info_rec_size> sections[while($ < End)];
};

struct BPFLine {
  u32 line_col;
} [[format("format_bpf_line_col"), sealed]];

fn format_bpf_line_col(BPFLine line) {
  u32 num = line.line_col >> 10;
  u32 col = line.line_col & 0x3ff;

  return std::format("{}:{}", num, col);
};

struct BPFLineInfo {
  u32 insn_off;
  u32 file_name_off;
  u32 line_off;
  BPFLine line_col;
};

struct BTFExtInfoSec_LineInfo<auto RecSize> : BTFExtInfoSec<RecSize> {
  u32 end = addressof(data) + sizeof(data);
  BPFLineInfo line_infos[while($<end)] @ addressof(data);
};

struct BTFLineInfo<auto End> {
  u32 line_info_rec_size;
  BTFExtInfoSec_LineInfo<line_info_rec_size> sections[while($ < End)];
};

struct BPFCORERelo {
  u32 ins_off;
  u32 type_id;
  u32 access_str_off;
  u32 kind;
};

struct BTFExtInfoSec_CORE<auto RecSize> : BTFExtInfoSec<RecSize> {
  u32 end = addressof(data) + sizeof(data);
  BPFCORERelo relocations[while($<end)] @ addressof(data);
};

struct BTFCORERelo<auto End> {
  u32 core_relo_rec_size;
  BTFExtInfoSec_CORE<core_relo_rec_size> sections[while($ < End)];
};


struct BTFExt {
  BTFExtHeader hdr;

  u32 func_info_end = $+hdr.func_info_off+hdr.func_info_len;
  u32 line_info_end = $+hdr.line_info_off+hdr.line_info_len;
  u32 core_relo_end = $+hdr.core_relo_off+hdr.core_relo_len;

  BTFFuncInfo<func_info_end> func_info;
  BTFLineInfo<line_info_end> line_info;
  BTFCORERelo<core_relo_end> core_relo;
};

u32 data_start = 0x90;
u32 data_len = 1292;

//BTF btf @ data_start;
ELF elf @0x00;

u32 btf_start = 0x00;
u32 btf_ext_start = 0x00;

for (u32 i = 0, i < std::core::member_count(elf.shdr), i += 1) {
  if(std::core::formatted_value(elf.shdr[i]) == ".BTF\0" ) {
     btf_start = elf.shdr[i].sh_offset;
     continue;
  }
  if(std::core::formatted_value(elf.shdr[i]) == ".BTF.ext\0" ) {
     btf_ext_start = elf.shdr[i].sh_offset;
     continue;
  }
}

BTF btf @ btf_start;
BTFExt btf_ext @ btf_ext_start;

std::string::NullString s @ addressof(btf.strings)+272;
