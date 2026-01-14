from dissect.cstruct import cstruct

hbk_def = """
struct virtual_file_entry {
    uint16            file_chunk_id;
    uint16            pool;
    uint32            chunk_list_offset;
    uint32            unk0;
    uint32            unk1;
    uint32            unk2;
    uint32            unk3;
    uint32            unk4;
    uint32            unk5;
    uint32            unk6;
    uint32            unk7;
    uint32            unk8;
    uint32            unk9;
    uint32            unk10;
    uint32            unk11;
};

struct virtual_file_chunk_entry {
    uint32          unk_but_probably_some_sub_pool_id;
    uint32          subindex_and_offset;
}

struct virtual_file_chunk_list {
    uint16          unk0;
    uint16          unk1;
    uint32          unk2;
    uint32          unk3;
    uint16          unk4;
    uint16          unk5;
    uint32          len;
    virtual_file_chunk_entry chunks[len - 8 >> 3];  // Divide by 8
    uint32          unk6;
    uint32          unk7;
};

struct chunk_pool_info {
    uint16         p1;
    uint16         p2;
    uint8          pool;
    uint32         chunk_offset;
    uint32         original_size;
    uint32         unk2;
    uint32         unk3;
    uint32         unk4;
    uint32         checksum;
};

struct chunk_pool_data {
    uint32         length;
    uint32         offset;
    uint32         uncompressed_length;
    uint32         unk2;
    uint32         unk3;
    uint32         unk4;
    uint32         unk5;
    uint32         unk6;
};
"""

c_hbk = cstruct(endian=">").load(hbk_def)
