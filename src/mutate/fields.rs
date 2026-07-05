use crate::image::FieldWidth;

pub(super) const EROFS_FEATURE_COMPAT_XATTR_FILTER: u64 = 0x00000004;
pub(super) const EROFS_FEATURE_COMPAT_PLAIN_XATTR_PFX: u64 = 0x00000010;
pub(super) const EROFS_FEATURE_COMPAT_ISHARE_XATTRS: u64 = 0x00000020;
pub(super) const EROFS_FEATURE_INCOMPAT_48BIT: u32 = 0x00000080;
pub(super) const EROFS_FEATURE_INCOMPAT_DEVICE_TABLE: u64 = 0x00000008;
pub(super) const EROFS_FEATURE_INCOMPAT_FRAGMENTS: u64 = 0x00000020;
pub(super) const EROFS_FEATURE_INCOMPAT_XATTR_PREFIXES: u64 = 0x00000040;
pub(super) const EROFS_INODE_COMPRESSED_FULL: u64 = 1;
pub(super) const EROFS_INODE_COMPRESSED_COMPACT: u64 = 3;
pub(super) const EROFS_INODE_CHUNK_BASED: u64 = 4;
pub(super) const EROFS_INODE_SLOT_SIZE: usize = 32;
pub(super) const EROFS_XATTR_FILTER_DEFAULT: u64 = 0xFFFF_FFFF;
pub(super) const EROFS_XATTR_LONG_PREFIX: u64 = 0x80;
pub(super) const EROFS_CHUNK_FORMAT_INDEXES: u64 = 0x0020;
pub(super) const EROFS_CHUNK_FORMAT_UNSUPPORTED_BIT: u64 = 0x0080;
pub(super) const EROFS_DEVT_SLOT_SIZE: usize = 128;
pub(super) const Z_EROFS_ADVISE_BIG_PCLUSTER_1: u64 = 0x0002;
pub(super) const Z_EROFS_ADVISE_BIG_PCLUSTER_2: u64 = 0x0004;
pub(super) const Z_EROFS_ADVISE_UNSUPPORTED_BIT: u64 = 0x8000;
pub(super) const Z_EROFS_CLUSTERBITS_RESERVED_BIT: u64 = 0x10;
pub(super) const Z_EROFS_FRAGMENT_INODE_MASK: u64 = 1 << 63;
pub(super) const Z_EROFS_MAP_HEADER_SIZE: usize = 8;

/// A single field mutation definition.
pub(super) struct MutationDef {
    pub(super) field_offset: usize,
    pub(super) width: FieldWidth,
    pub(super) field_name: &'static str,
    pub(super) values: &'static [(u64, &'static str)],
}

/// Superblock mutation table.
pub(super) const SUPERBLOCK_FIELDS: &[MutationDef] = &[
    MutationDef {
        field_offset: 0x00,
        width: FieldWidth::U32,
        field_name: "magic",
        values: &[
            (0x00000000, "zero"),
            (0xFFFFFFFF, "all_ones"),
            (0xE0F5E1E1, "off_by_one_low"),
            (0xE0F5E1E3, "off_by_one_high"),
            (0xE1F5E0E2, "byte_swap"),
            (0x12345678, "random"),
        ],
    },
    MutationDef {
        field_offset: 0x04,
        width: FieldWidth::U32,
        field_name: "checksum",
        values: &[
            (0x00000000, "zero"),
            (0xFFFFFFFF, "all_ones"),
            (0x12345678, "random"),
        ],
    },
    MutationDef {
        field_offset: 0x08,
        width: FieldWidth::U32,
        field_name: "feature_compat",
        values: &[
            (0x00000000, "clear_all"),
            (0xFFFFFFFF, "all_ones"),
            (EROFS_FEATURE_COMPAT_XATTR_FILTER, "set_xattr_filter"),
            (
                EROFS_FEATURE_COMPAT_PLAIN_XATTR_PFX,
                "set_plain_xattr_prefix",
            ),
            (EROFS_FEATURE_COMPAT_ISHARE_XATTRS, "set_ishare_xattrs"),
            (0x00000040, "set_unknown_compat_bit"),
        ],
    },
    MutationDef {
        field_offset: 0x0C,
        width: FieldWidth::U8,
        field_name: "blkszbits",
        values: &[
            (0x00, "zero"),
            (0x01, "one"),
            (0x0B, "2048_bytes"),
            (0x0D, "8192_bytes"),
            (0x1F, "max"),
            (0x20, "overflow"),
        ],
    },
    MutationDef {
        field_offset: 0x0D,
        width: FieldWidth::U8,
        field_name: "sb_extslots",
        values: &[(0x00, "zero"), (0x01, "one"), (0xFF, "max")],
    },
    MutationDef {
        field_offset: 0x0E,
        width: FieldWidth::U16,
        field_name: "rootnid",
        values: &[(0x0000, "zero"), (0x0001, "one"), (0xFFFF, "max")],
    },
    MutationDef {
        field_offset: 0x10,
        width: FieldWidth::U64,
        field_name: "inos",
        values: &[
            (0x0000000000000000, "zero"),
            (0xFFFFFFFFFFFFFFFF, "max"),
            (0x0000000000000001, "one_less"),
            (0x0000000000000003, "one_more"),
        ],
    },
    MutationDef {
        field_offset: 0x18,
        width: FieldWidth::U64,
        field_name: "epoch",
        values: &[
            (0x0000000000000000, "zero"),
            (0x0000000000000001, "one"),
            (0xFFFFFFFFFFFFFFFF, "max"),
        ],
    },
    MutationDef {
        field_offset: 0x20,
        width: FieldWidth::U32,
        field_name: "fixed_nsec",
        values: &[
            (0x00000000, "zero"),
            (0x3B9AC9FF, "max_valid_nsec"),
            (0x3B9ACA00, "one_billion"),
            (0xFFFFFFFF, "max"),
        ],
    },
    MutationDef {
        field_offset: 0x24,
        width: FieldWidth::U32,
        field_name: "blocks_lo",
        values: &[
            (0x00000000, "zero"),
            (0xFFFFFFFF, "max"),
            (0x00000002, "one_more"),
        ],
    },
    MutationDef {
        field_offset: 0x28,
        width: FieldWidth::U32,
        field_name: "meta_blkaddr",
        values: &[
            (0x00000000, "zero"),
            (0xFFFFFFFF, "max"),
            (0x00000001, "point_to_data"),
        ],
    },
    MutationDef {
        field_offset: 0x2C,
        width: FieldWidth::U32,
        field_name: "xattr_blkaddr",
        values: &[(0x00000001, "point_to_data"), (0xFFFFFFFF, "max")],
    },
    MutationDef {
        field_offset: 0x30,
        width: FieldWidth::U64,
        field_name: "uuid_lo",
        values: &[(0x0000000000000000, "zero"), (0xFFFFFFFFFFFFFFFF, "max")],
    },
    MutationDef {
        field_offset: 0x38,
        width: FieldWidth::U64,
        field_name: "uuid_hi",
        values: &[(0x0000000000000000, "zero"), (0xFFFFFFFFFFFFFFFF, "max")],
    },
    MutationDef {
        field_offset: 0x40,
        width: FieldWidth::U64,
        field_name: "volume_name_lo",
        values: &[(0x0000000000000000, "zero"), (0xFFFFFFFFFFFFFFFF, "max")],
    },
    MutationDef {
        field_offset: 0x48,
        width: FieldWidth::U64,
        field_name: "volume_name_hi",
        values: &[(0x0000000000000000, "zero"), (0xFFFFFFFFFFFFFFFF, "max")],
    },
    MutationDef {
        field_offset: 0x50,
        width: FieldWidth::U32,
        field_name: "feature_incompat",
        values: &[
            (0x00000000, "clear_all"),
            (0x00000004, "chunked_file"),
            (0x00000008, "device_or_compr_head2"),
            (0x00000020, "fragments_or_dedupe"),
            (0x00000040, "xattr_prefixes"),
            (0x00000080, "48bit"),
            (0x00000100, "metabox"),
            (0x00000200, "unknown_bit"),
            (0xFFFFFFFF, "all_ones"),
        ],
    },
    MutationDef {
        field_offset: 0x54,
        width: FieldWidth::U16,
        field_name: "available_compr_algs",
        values: &[
            (0x0000, "zero"),
            (0x0001, "lz4"),
            (0x0002, "secondary"),
            (0xFFFF, "max"),
        ],
    },
    MutationDef {
        field_offset: 0x56,
        width: FieldWidth::U16,
        field_name: "extra_devices",
        values: &[(0x0000, "zero"), (0x0001, "one"), (0xFFFF, "max")],
    },
    MutationDef {
        field_offset: 0x58,
        width: FieldWidth::U16,
        field_name: "devt_slotoff",
        values: &[(0x0000, "zero"), (0x0001, "one"), (0xFFFF, "max")],
    },
    MutationDef {
        field_offset: 0x5A,
        width: FieldWidth::U8,
        field_name: "dirblkbits",
        values: &[
            (0x00, "zero"),
            (0x01, "one"),
            (0x0C, "block_bits"),
            (0xFF, "max"),
        ],
    },
    MutationDef {
        field_offset: 0x5B,
        width: FieldWidth::U8,
        field_name: "xattr_prefix_count",
        values: &[(0x00, "zero"), (0x01, "one"), (0xFF, "max")],
    },
    MutationDef {
        field_offset: 0x5C,
        width: FieldWidth::U32,
        field_name: "xattr_prefix_start",
        values: &[
            (0x00000000, "zero"),
            (0x00000001, "one"),
            (0xFFFFFFFF, "max"),
        ],
    },
    MutationDef {
        field_offset: 0x60,
        width: FieldWidth::U64,
        field_name: "packed_nid",
        values: &[
            (0x0000000000000000, "zero"),
            (0x0000000000000001, "one"),
            (0xFFFFFFFFFFFFFFFF, "max"),
        ],
    },
    MutationDef {
        field_offset: 0x68,
        width: FieldWidth::U8,
        field_name: "xattr_filter_reserved",
        values: &[(0x00, "zero"), (0x01, "one"), (0xFF, "max")],
    },
    MutationDef {
        field_offset: 0x69,
        width: FieldWidth::U8,
        field_name: "ishare_xattr_prefix_id",
        values: &[(0x00, "zero"), (0x01, "one"), (0xFF, "max")],
    },
    MutationDef {
        field_offset: 0x6A,
        width: FieldWidth::U16,
        field_name: "reserved",
        values: &[(0x0000, "zero"), (0xFFFF, "max")],
    },
    MutationDef {
        field_offset: 0x6C,
        width: FieldWidth::U32,
        field_name: "build_time",
        values: &[
            (0x00000000, "zero"),
            (0x00000001, "one"),
            (0xFFFFFFFF, "max"),
        ],
    },
    MutationDef {
        field_offset: 0x70,
        width: FieldWidth::U64,
        field_name: "root_nid_8b",
        values: &[
            (0x0000000000000000, "zero"),
            (0x0000000000000001, "one"),
            (0xFFFFFFFFFFFFFFFF, "max"),
        ],
    },
    MutationDef {
        field_offset: 0x78,
        width: FieldWidth::U64,
        field_name: "reserved2",
        values: &[(0x0000000000000000, "zero"), (0xFFFFFFFFFFFFFFFF, "max")],
    },
    MutationDef {
        field_offset: 0x80,
        width: FieldWidth::U64,
        field_name: "metabox_nid",
        values: &[
            (0x0000000000000000, "zero"),
            (0x0000000000000001, "one"),
            (0xFFFFFFFFFFFFFFFF, "max"),
        ],
    },
    MutationDef {
        field_offset: 0x88,
        width: FieldWidth::U64,
        field_name: "reserved3",
        values: &[(0x0000000000000000, "zero"), (0xFFFFFFFFFFFFFFFF, "max")],
    },
];

/// Inode mutation table.
pub(super) const INODE_FIELDS: &[MutationDef] = &[
    MutationDef {
        field_offset: 0x00,
        width: FieldWidth::U16,
        field_name: "i_format",
        values: &[
            (0x0000, "version_compact_datalayout_plain"),
            (0x0001, "version_extended_datalayout_plain"),
            (0x0002, "version_compact_datalayout_compressed_full"),
            (0x0003, "version_extended_datalayout_compressed_full"),
            (0x0004, "version_compact_datalayout_flat_inline"),
            (0x0005, "version_extended_datalayout_flat_inline"),
            (0x0006, "version_compact_datalayout_compressed_compact"),
            (0x0007, "version_extended_datalayout_compressed_compact"),
            (0x0008, "version_compact_datalayout_chunk_based"),
            (0x0009, "version_extended_datalayout_chunk_based"),
            (0x0010, "nlink_1_bit_set"),
            (0x00FF, "all_ones"),
        ],
    },
    MutationDef {
        field_offset: 0x02,
        width: FieldWidth::U16,
        field_name: "i_xattr_icount",
        values: &[(0x0000, "zero"), (0x0001, "one"), (0x00FF, "max")],
    },
    MutationDef {
        field_offset: 0x04,
        width: FieldWidth::U16,
        field_name: "i_mode",
        values: &[
            (0x0000, "zero"),
            (0x1000, "fifo"),
            (0x2000, "chrdev"),
            (0x4000, "dir"),
            (0x6000, "blkdev"),
            (0x8000, "regular"),
            (0xA000, "symlink"),
            (0xC000, "socket"),
            (0x81A4, "reg_0644"),
            (0x41C0, "dir_0700"),
            (0xFFFF, "all_ones"),
        ],
    },
    MutationDef {
        field_offset: 0x06,
        width: FieldWidth::U16,
        field_name: "i_nb.nlink",
        values: &[(0x0000, "zero"), (0x0001, "one"), (0xFFFF, "max")],
    },
    MutationDef {
        field_offset: 0x08,
        width: FieldWidth::U32,
        field_name: "i_size",
        values: &[
            (0x00000000, "zero"),
            (0x00000001, "one"),
            (0xFFFFFFFF, "max"),
            (0x00001000, "one_block"),
            (0x00100000, "one_mb"),
        ],
    },
    MutationDef {
        field_offset: 0x0C,
        width: FieldWidth::U32,
        field_name: "i_mtime",
        values: &[(0x00000000, "zero"), (0xFFFFFFFF, "max")],
    },
    MutationDef {
        field_offset: 0x10,
        width: FieldWidth::U32,
        field_name: "i_u.startblk_lo",
        values: &[
            (0x00000000, "zero"),
            (0x00000001, "block_1"),
            (0xFFFFFFFF, "max"),
        ],
    },
    MutationDef {
        field_offset: 0x14,
        width: FieldWidth::U32,
        field_name: "i_ino",
        values: &[(0x00000000, "zero"), (0xFFFFFFFF, "max")],
    },
    MutationDef {
        field_offset: 0x18,
        width: FieldWidth::U16,
        field_name: "i_uid",
        values: &[(0x0000, "zero"), (0x03E8, "original_1000"), (0xFFFF, "max")],
    },
    MutationDef {
        field_offset: 0x1A,
        width: FieldWidth::U16,
        field_name: "i_gid",
        values: &[(0x0000, "zero"), (0x03E8, "original_1000"), (0xFFFF, "max")],
    },
];

pub(super) fn inode_field_location(
    field_name: &str,
    extended: bool,
) -> Option<(usize, FieldWidth)> {
    let location = match field_name {
        "i_format" => (0x00, FieldWidth::U16),
        "i_xattr_icount" => (0x02, FieldWidth::U16),
        "i_mode" => (0x04, FieldWidth::U16),
        "i_nb.nlink" if extended => (0x28, FieldWidth::U32),
        "i_nb.nlink" => (0x06, FieldWidth::U16),
        "i_size" if extended => (0x08, FieldWidth::U64),
        "i_size" => (0x08, FieldWidth::U32),
        "i_mtime" if extended => (0x20, FieldWidth::U64),
        "i_mtime" => (0x0C, FieldWidth::U32),
        "i_u.startblk_lo" => (0x10, FieldWidth::U32),
        "i_ino" => (0x14, FieldWidth::U32),
        "i_uid" if extended => (0x18, FieldWidth::U32),
        "i_uid" => (0x18, FieldWidth::U16),
        "i_gid" if extended => (0x1C, FieldWidth::U32),
        "i_gid" => (0x1A, FieldWidth::U16),
        _ => return None,
    };
    Some(location)
}

/// Directory entry mutation table.
pub(super) const DIRENT_FIELDS: &[MutationDef] = &[
    MutationDef {
        field_offset: 0x00,
        width: FieldWidth::U64,
        field_name: "nid",
        values: &[
            (0x0000000000000000, "zero"),
            (0x0000000000000001, "one"),
            (0x00000000000000FF, "small"),
            (0xFFFFFFFFFFFFFFFF, "max"),
            (0x0000000000000024, "self_ref"),
        ],
    },
    MutationDef {
        field_offset: 0x08,
        width: FieldWidth::U16,
        field_name: "nameoff",
        values: &[
            (0x0000, "zero"),
            (0x0001, "one"),
            (0x00FF, "max_byte"),
            (0x0FFF, "max_4k"),
            (0xFFFF, "max"),
            (0x0028, "point_to_inode"),
            (0x1000, "beyond_block"),
        ],
    },
    MutationDef {
        field_offset: 0x0A,
        width: FieldWidth::U8,
        field_name: "file_type",
        values: &[
            (0x00, "unknown"),
            (0x01, "reg_file"),
            (0x02, "dir"),
            (0x03, "chrdev"),
            (0x04, "blkdev"),
            (0x05, "fifo"),
            (0x06, "sock"),
            (0x07, "symlink"),
            (0x08, "invalid_8"),
            (0x0F, "invalid_15"),
            (0xFF, "invalid_max"),
        ],
    },
    MutationDef {
        field_offset: 0x0B,
        width: FieldWidth::U8,
        field_name: "reserved",
        values: &[(0x00, "zero"), (0xFF, "max")],
    },
];
