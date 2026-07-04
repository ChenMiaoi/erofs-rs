use crate::image::{Image, Superblock};
use anyhow::{Result, bail};

const SLOT_SIZE: usize = 32;
const EROFS_NULL_ADDR_32: u32 = u32::MAX;

/// A located inode.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Inode {
    /// Byte offset of the inode in the image.
    pub offset: usize,
    /// NID (slot index).
    pub nid: u64,
    /// Human-readable description.
    pub desc: String,
}

fn checked_range_end(offset: usize, width: usize) -> Result<usize> {
    offset
        .checked_add(width)
        .ok_or_else(|| anyhow::anyhow!("offset 0x{offset:X} + {width} overflows"))
}

fn read_i_format(image: &Image, offset: usize) -> Result<u16> {
    let end = checked_range_end(offset, 2)?;
    if end > image.len() {
        bail!("inode offset out of bounds");
    }
    Ok(u16::from_le_bytes([
        image.as_bytes()[offset],
        image.as_bytes()[offset + 1],
    ]))
}

/// Return the on-disk inode size (32 or 64) by reading the version bit.
pub fn inode_size(image: &Image, offset: usize) -> Result<usize> {
    let i_format = read_i_format(image, offset)?;
    Ok(if (i_format & 0x01) != 0 { 64 } else { 32 })
}

/// Return whether the inode uses the 64-byte extended layout.
pub fn is_extended_inode(image: &Image, offset: usize) -> Result<bool> {
    Ok(inode_size(image, offset)? == 64)
}

/// Heuristic: does the byte pattern at offset look like an inode?
pub fn is_plausible_inode(image: &Image, offset: usize, expected_ino: Option<u32>) -> bool {
    let Some(min_end) = offset.checked_add(32) else {
        return false;
    };
    if min_end > image.len() {
        return false;
    }
    let data = image.as_bytes();
    let i_format = u16::from_le_bytes([data[offset], data[offset + 1]]);
    let version = i_format & 0x1;
    let layout = (i_format >> 1) & 0x7;
    let xattr_icount = u16::from_le_bytes([data[offset + 2], data[offset + 3]]);
    let mode = u16::from_le_bytes([data[offset + 4], data[offset + 5]]);
    let file_type = mode >> 12;

    if layout > 4 {
        return false;
    }
    if !matches!(file_type, 0 | 1 | 2 | 4 | 6 | 8 | 10 | 12 | 14) {
        return false;
    }
    if xattr_icount > 32 {
        return false;
    }

    if version == 0 {
        // compact inode: i_reserved at 0x1C must be 0
        let reserved = u32::from_le_bytes([
            data[offset + 0x1C],
            data[offset + 0x1D],
            data[offset + 0x1E],
            data[offset + 0x1F],
        ]);
        if reserved != 0 {
            return false;
        }
        if let Some(expected) = expected_ino {
            let ino = u32::from_le_bytes([
                data[offset + 0x14],
                data[offset + 0x15],
                data[offset + 0x16],
                data[offset + 0x17],
            ]);
            if ino != expected {
                return false;
            }
        }
    } else {
        // extended inode: i_reserved at 0x38-0x3F should be 0
        let Some(extended_end) = offset.checked_add(0x40) else {
            return false;
        };
        if extended_end > data.len() {
            return false;
        }
        let reserved = u64::from_le_bytes([
            data[offset + 0x38],
            data[offset + 0x39],
            data[offset + 0x3A],
            data[offset + 0x3B],
            data[offset + 0x3C],
            data[offset + 0x3D],
            data[offset + 0x3E],
            data[offset + 0x3F],
        ]);
        if reserved != 0 {
            return false;
        }
        if let Some(expected) = expected_ino {
            let ino = u32::from_le_bytes([
                data[offset + 0x14],
                data[offset + 0x15],
                data[offset + 0x16],
                data[offset + 0x17],
            ]);
            if ino != expected {
                return false;
            }
        }
    }

    true
}

fn round_up(val: usize, align: usize) -> Result<usize> {
    val.checked_add(align - 1)
        .map(|v| v & !(align - 1))
        .ok_or_else(|| anyhow::anyhow!("round_up({val}, {align}) overflows"))
}

fn xattr_ibody_size(i_xattr_icount: u16) -> Result<usize> {
    if i_xattr_icount == 0 {
        return Ok(0);
    }
    12usize
        .checked_add(
            ((i_xattr_icount as usize) - 1)
                .checked_mul(4)
                .ok_or_else(|| {
                    anyhow::anyhow!("inode xattr body size overflows: {i_xattr_icount}")
                })?,
        )
        .ok_or_else(|| anyhow::anyhow!("inode xattr body size overflows: {i_xattr_icount}"))
}

fn inode_xattr_size(image: &Image, inode_offset: usize) -> Result<usize> {
    let end = checked_range_end(inode_offset, 4)?;
    if end > image.len() {
        bail!("inode offset out of bounds");
    }
    let data = image.as_bytes();
    let i_xattr_icount = u16::from_le_bytes([data[inode_offset + 2], data[inode_offset + 3]]);
    xattr_ibody_size(i_xattr_icount)
}

pub fn inode_file_size(image: &Image, inode_offset: usize) -> Result<u64> {
    let inode_size = inode_size(image, inode_offset)?;
    let required = if inode_size == 64 { 16 } else { 12 };
    let end = checked_range_end(inode_offset, required)?;
    if end > image.len() {
        bail!("inode offset out of bounds");
    }
    let data = image.as_bytes();
    if inode_size == 64 {
        Ok(u64::from_le_bytes([
            data[inode_offset + 8],
            data[inode_offset + 9],
            data[inode_offset + 10],
            data[inode_offset + 11],
            data[inode_offset + 12],
            data[inode_offset + 13],
            data[inode_offset + 14],
            data[inode_offset + 15],
        ]))
    } else {
        Ok(u32::from_le_bytes([
            data[inode_offset + 8],
            data[inode_offset + 9],
            data[inode_offset + 10],
            data[inode_offset + 11],
        ]) as u64)
    }
}

fn inode_offset_for_nid(sb: &Superblock, nid: u64) -> Result<usize> {
    let nid_offset = usize::try_from(nid)
        .map_err(|_| anyhow::anyhow!("nid {nid} does not fit host usize"))?
        .checked_mul(SLOT_SIZE)
        .ok_or_else(|| anyhow::anyhow!("nid {nid} inode offset overflows"))?;
    sb.meta_offset
        .checked_add(nid_offset)
        .ok_or_else(|| anyhow::anyhow!("nid {nid} inode offset overflows"))
}

/// Number of 32-byte inode-table slots this inode and its inline payload occupy.
pub fn slots_occupied(image: &Image, sb: &Superblock, inode_offset: usize) -> Result<usize> {
    if checked_range_end(inode_offset, 2)? > image.len() {
        bail!("inode offset out of bounds");
    }
    let data = image.as_bytes();
    let i_format = u16::from_le_bytes([data[inode_offset], data[inode_offset + 1]]);
    let version = i_format & 0x1;
    let datalayout = (i_format >> 1) & 0x7;
    let inode_size = if version != 0 { 64 } else { 32 };
    if checked_range_end(inode_offset, inode_size)? > image.len() {
        bail!("inode offset out of bounds");
    }

    let total = if datalayout == 2 {
        // EROFS_INODE_FLAT_INLINE
        let i_size = inode_file_size(image, inode_offset)?;
        let inline_size = if i_size <= sb.block_size as u64 {
            usize::try_from(i_size)
                .map_err(|_| anyhow::anyhow!("inline inode size does not fit host usize"))?
        } else {
            usize::try_from(i_size % sb.block_size as u64)
                .map_err(|_| anyhow::anyhow!("inline inode tail size does not fit host usize"))?
        };
        inode_size
            .checked_add(inode_xattr_size(image, inode_offset)?)
            .and_then(|v| v.checked_add(round_up(inline_size, SLOT_SIZE).ok()?))
            .ok_or_else(|| anyhow::anyhow!("inode slot usage overflows"))?
    } else {
        inode_size
            .checked_add(inode_xattr_size(image, inode_offset)?)
            .ok_or_else(|| anyhow::anyhow!("inode slot usage overflows"))?
    };

    Ok(std::cmp::max(1, round_up(total, SLOT_SIZE)? / SLOT_SIZE))
}

/// Locate inodes in the inode table.
pub fn locate_inodes(image: &Image, sb: &Superblock) -> Result<Vec<Inode>> {
    let root_nid = sb.rootnid;
    let inos = usize::try_from(sb.inos).unwrap_or(usize::MAX);
    let mut slot = root_nid;
    let mut expected_ino: u32 = 1;
    let mut inodes = Vec::new();
    let max_inodes = inos.max(1024);

    while inodes.len() < max_inodes {
        let offset = match inode_offset_for_nid(sb, slot) {
            Ok(offset) => offset,
            Err(_) => break,
        };
        if checked_range_end(offset, SLOT_SIZE)? > image.len() {
            break;
        }

        if is_plausible_inode(image, offset, Some(expected_ino)) {
            let desc = if slot == root_nid {
                "root_directory".to_string()
            } else {
                format!("inode_{slot}")
            };
            inodes.push(Inode {
                offset,
                nid: slot,
                desc,
            });
            expected_ino += 1;
            let occupied = u64::try_from(slots_occupied(image, sb, offset)?)
                .map_err(|_| anyhow::anyhow!("inode slot count does not fit u64"))?;
            slot = slot
                .checked_add(occupied)
                .ok_or_else(|| anyhow::anyhow!("inode slot scan overflows"))?;
        } else {
            slot = slot
                .checked_add(1)
                .ok_or_else(|| anyhow::anyhow!("inode slot scan overflows"))?;
        }
    }

    Ok(inodes)
}

/// Check whether the inode at offset is a directory.
pub fn is_directory_inode(image: &Image, inode_offset: usize) -> Result<bool> {
    if checked_range_end(inode_offset, 6)? > image.len() {
        bail!("inode offset out of bounds");
    }
    let data = image.as_bytes();
    let mode = u16::from_le_bytes([data[inode_offset + 4], data[inode_offset + 5]]);
    Ok(((mode >> 12) & 0xF) == 4)
}

/// Return the start offset of the inode's data (for flat layouts).
pub fn inode_data_offset(image: &Image, sb: &Superblock, inode_offset: usize) -> Result<usize> {
    if checked_range_end(inode_offset, 18)? > image.len() {
        bail!("inode offset out of bounds");
    }
    let data = image.as_bytes();
    let i_format = u16::from_le_bytes([data[inode_offset], data[inode_offset + 1]]);
    let version = i_format & 0x1;
    let layout = (i_format >> 1) & 0x7;
    let inode_size = if version != 0 { 64 } else { 32 };
    if checked_range_end(inode_offset, inode_size)? > image.len() {
        bail!("inode offset out of bounds");
    }

    if layout == 2 {
        // flat_inline: data follows the inode
        return inode_offset
            .checked_add(inode_size)
            .and_then(|v| v.checked_add(inode_xattr_size(image, inode_offset).ok()?))
            .ok_or_else(|| anyhow::anyhow!("inline data offset overflows"));
    }

    if layout == 4 {
        bail!("chunk-based inode data offset requires chunk map parsing");
    }
    if layout == 1 || layout == 3 {
        bail!("compressed inode data offset requires compression map parsing");
    }
    if layout > 4 {
        bail!("unsupported EROFS inode data layout: {layout}");
    }

    // flat_plain: startblk is a physical filesystem block number.
    let startblk_lo = u32::from_le_bytes([
        data[inode_offset + 0x10],
        data[inode_offset + 0x11],
        data[inode_offset + 0x12],
        data[inode_offset + 0x13],
    ]);
    let startblk_hi = u16::from_le_bytes([data[inode_offset + 0x06], data[inode_offset + 0x07]]);
    if startblk_lo == EROFS_NULL_ADDR_32 && startblk_hi == u16::MAX {
        bail!("flat inode has no mapped data blocks");
    }
    let startblk = (startblk_lo as u64) | ((startblk_hi as u64) << 32);
    usize::try_from(startblk)
        .map_err(|_| anyhow::anyhow!("start block does not fit host usize"))?
        .checked_mul(sb.block_size as usize)
        .ok_or_else(|| anyhow::anyhow!("data offset overflows"))
}
