use anyhow::{Result, bail};
use std::fs;
use std::path::Path;

/// Byte offset of the EROFS superblock.
pub const EROFS_SUPER_OFFSET: usize = 1024;
/// EROFS magic value.
pub const EROFS_MAGIC: u32 = 0xE0F5E1E2;
const EROFS_MIN_BLOCK_BITS: u8 = 9;
const EROFS_MAX_BLOCK_BITS: u8 = 12;
const EROFS_FEATURE_INCOMPAT_48BIT: u32 = 0x00000080;
const EROFS_SB_EXTSLOT_SIZE: usize = 16;
const EROFS_PAGE_SIZE: usize = 4096;

/// In-memory representation of an EROFS image.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Image {
    data: Vec<u8>,
}

impl Image {
    /// Create an image from raw bytes.
    pub fn new(data: Vec<u8>) -> Self {
        Self { data }
    }

    /// Return a reference to the raw bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }

    /// Return a mutable reference to the raw bytes.
    pub fn as_bytes_mut(&mut self) -> &mut [u8] {
        &mut self.data
    }

    /// Return the image size.
    pub fn len(&self) -> usize {
        self.data.len()
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Read a little-endian unsigned integer of the given width.
    pub fn read_field(&self, offset: usize, width: FieldWidth) -> Result<u64> {
        let end = offset
            .checked_add(width.bytes())
            .ok_or_else(|| anyhow::anyhow!("offset 0x{offset:X} + {} overflows", width.bytes()))?;
        let bytes = self
            .data
            .get(offset..end)
            .ok_or_else(|| anyhow::anyhow!("offset 0x{offset:X} out of bounds"))?;
        Ok(match width {
            FieldWidth::U8 => bytes[0] as u64,
            FieldWidth::U16 => u16::from_le_bytes([bytes[0], bytes[1]]) as u64,
            FieldWidth::U32 => u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as u64,
            FieldWidth::U64 => u64::from_le_bytes([
                bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
            ]),
        })
    }

    /// Write a little-endian unsigned integer of the given width.
    pub fn write_field(&mut self, offset: usize, width: FieldWidth, value: u64) -> Result<()> {
        if value > width.max_value() {
            bail!(
                "value 0x{value:X} does not fit in {} byte(s)",
                width.bytes()
            );
        }
        let end = offset
            .checked_add(width.bytes())
            .ok_or_else(|| anyhow::anyhow!("offset 0x{offset:X} + {} overflows", width.bytes()))?;
        if end > self.data.len() {
            bail!("offset 0x{offset:X} + {} out of bounds", width.bytes());
        }
        let bytes = &mut self.data[offset..end];
        match width {
            FieldWidth::U8 => bytes[0] = (value & 0xFF) as u8,
            FieldWidth::U16 => bytes.copy_from_slice(&(value as u16).to_le_bytes()),
            FieldWidth::U32 => bytes.copy_from_slice(&(value as u32).to_le_bytes()),
            FieldWidth::U64 => bytes.copy_from_slice(&value.to_le_bytes()),
        }
        Ok(())
    }

    /// Parse the EROFS superblock.
    pub fn superblock(&self) -> Result<Superblock> {
        Superblock::parse(self)
    }
}

/// Field width for raw injection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FieldWidth {
    U8,
    U16,
    U32,
    U64,
}

impl FieldWidth {
    pub fn bytes(&self) -> usize {
        match self {
            FieldWidth::U8 => 1,
            FieldWidth::U16 => 2,
            FieldWidth::U32 => 4,
            FieldWidth::U64 => 8,
        }
    }

    pub fn max_value(&self) -> u64 {
        match self {
            FieldWidth::U8 => u8::MAX as u64,
            FieldWidth::U16 => u16::MAX as u64,
            FieldWidth::U32 => u32::MAX as u64,
            FieldWidth::U64 => u64::MAX,
        }
    }
}

impl std::str::FromStr for FieldWidth {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "u8" => Ok(FieldWidth::U8),
            "u16" => Ok(FieldWidth::U16),
            "u32" => Ok(FieldWidth::U32),
            "u64" => Ok(FieldWidth::U64),
            _ => bail!("unsupported width: {s} (expected u8/u16/u32/u64)"),
        }
    }
}

/// Key fields parsed from the EROFS superblock.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Superblock {
    pub magic: u32,
    pub checksum: u32,
    pub feature_compat: u32,
    pub feature_incompat: u32,
    pub blkszbits: u8,
    pub sb_extslots: u8,
    pub rootnid: u64,
    pub inos: u64,
    pub blocks_lo: u32,
    pub meta_blkaddr: u32,
    pub xattr_blkaddr: u32,
    pub extra_devices: u16,
    pub devt_slotoff: u16,
    pub dirblkbits: u8,
    pub block_size: u32,
    pub sb_size: usize,
    pub meta_offset: usize,
}

impl Superblock {
    /// Parse the superblock from an image.
    pub fn parse(image: &Image) -> Result<Self> {
        let sb = EROFS_SUPER_OFFSET;
        if sb + 0x5C > image.len() {
            bail!("image too small to contain superblock");
        }
        let data = image.as_bytes();
        let blkszbits = data[sb + 0x0C];
        if !(EROFS_MIN_BLOCK_BITS..=EROFS_MAX_BLOCK_BITS).contains(&blkszbits) {
            bail!("unsupported EROFS blkszbits: {blkszbits}");
        }
        let block_size = 1u32
            .checked_shl(blkszbits.into())
            .ok_or_else(|| anyhow::anyhow!("invalid EROFS blkszbits: {blkszbits}"))?;
        let sb_extslots = data[sb + 0x0D];
        let sb_size = 128usize
            .checked_add(
                (sb_extslots as usize)
                    .checked_mul(EROFS_SB_EXTSLOT_SIZE)
                    .ok_or_else(|| {
                        anyhow::anyhow!("superblock extension slot count overflows: {sb_extslots}")
                    })?,
            )
            .ok_or_else(|| anyhow::anyhow!("superblock size overflows"))?;
        if sb_size > EROFS_PAGE_SIZE - EROFS_SUPER_OFFSET {
            bail!("invalid EROFS sb_extslots: {sb_extslots} (sb_size={sb_size})");
        }
        let meta_blkaddr = u32::from_le_bytes([
            data[sb + 0x28],
            data[sb + 0x29],
            data[sb + 0x2A],
            data[sb + 0x2B],
        ]);
        let meta_offset = (meta_blkaddr as usize)
            .checked_mul(block_size as usize)
            .ok_or_else(|| anyhow::anyhow!("meta_blkaddr offset overflows"))?;
        let feature_incompat = u32::from_le_bytes([
            data[sb + 0x50],
            data[sb + 0x51],
            data[sb + 0x52],
            data[sb + 0x53],
        ]);
        let dirblkbits = data[sb + 0x5A];
        if dirblkbits != 0 {
            bail!("unsupported EROFS dirblkbits: {dirblkbits}");
        }
        let rootnid_2b = u16::from_le_bytes([data[sb + 0x0E], data[sb + 0x0F]]) as u64;
        let rootnid =
            if feature_incompat & EROFS_FEATURE_INCOMPAT_48BIT != 0 && sb + 0x78 <= image.len() {
                let rootnid_8b = u64::from_le_bytes([
                    data[sb + 0x70],
                    data[sb + 0x71],
                    data[sb + 0x72],
                    data[sb + 0x73],
                    data[sb + 0x74],
                    data[sb + 0x75],
                    data[sb + 0x76],
                    data[sb + 0x77],
                ]);
                if rootnid_8b != 0 {
                    rootnid_8b
                } else {
                    rootnid_2b
                }
            } else {
                rootnid_2b
            };

        Ok(Self {
            magic: u32::from_le_bytes([data[sb], data[sb + 1], data[sb + 2], data[sb + 3]]),
            checksum: u32::from_le_bytes([data[sb + 4], data[sb + 5], data[sb + 6], data[sb + 7]]),
            feature_compat: u32::from_le_bytes([
                data[sb + 8],
                data[sb + 9],
                data[sb + 10],
                data[sb + 11],
            ]),
            feature_incompat,
            blkszbits,
            sb_extslots,
            rootnid,
            inos: u64::from_le_bytes([
                data[sb + 0x10],
                data[sb + 0x11],
                data[sb + 0x12],
                data[sb + 0x13],
                data[sb + 0x14],
                data[sb + 0x15],
                data[sb + 0x16],
                data[sb + 0x17],
            ]),
            blocks_lo: u32::from_le_bytes([
                data[sb + 0x24],
                data[sb + 0x25],
                data[sb + 0x26],
                data[sb + 0x27],
            ]),
            meta_blkaddr,
            xattr_blkaddr: u32::from_le_bytes([
                data[sb + 0x2C],
                data[sb + 0x2D],
                data[sb + 0x2E],
                data[sb + 0x2F],
            ]),
            extra_devices: u16::from_le_bytes([data[sb + 0x56], data[sb + 0x57]]),
            devt_slotoff: u16::from_le_bytes([data[sb + 0x58], data[sb + 0x59]]),
            dirblkbits,
            block_size,
            sb_size,
            meta_offset,
        })
    }
}

/// Read an image from disk.
pub fn read_image<P: AsRef<Path>>(path: P) -> Result<Image> {
    let data = fs::read(path.as_ref())
        .map_err(|e| anyhow::anyhow!("failed to read {}: {e}", path.as_ref().display()))?;
    Ok(Image::new(data))
}

/// Write an image to disk.
pub fn write_image<P: AsRef<Path>>(path: P, image: &Image) -> Result<()> {
    fs::write(path.as_ref(), image.as_bytes())
        .map_err(|e| anyhow::anyhow!("failed to write {}: {e}", path.as_ref().display()))?;
    Ok(())
}
