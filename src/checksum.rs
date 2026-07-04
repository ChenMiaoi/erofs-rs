use crate::image::{EROFS_SUPER_OFFSET, Image};
use anyhow::{Result, bail};

const CRC32C_POLY_LE: u32 = 0x82F63B78;

/// Compute CRC-32C (Castagnoli) over `data` starting from `init`.
///
/// This matches the bit-by-bit algorithm used by `erofs_crc32c` in the
/// reference implementation and keeps the raw polynomial state (no final XOR).
pub fn crc32c(init: u32, data: &[u8]) -> u32 {
    let mut crc = init;
    for &byte in data {
        crc ^= byte as u32;
        for _ in 0..8 {
            let mask = if crc & 1 == 1 { CRC32C_POLY_LE } else { 0 };
            crc = (crc >> 1) ^ mask;
        }
    }
    crc
}

/// Recalculate and patch the EROFS superblock checksum.
///
/// Returns `(old_checksum, new_checksum)`.
pub fn fix_checksum(image: &mut Image) -> Result<(u32, u32)> {
    let sb_offset = EROFS_SUPER_OFFSET;
    if sb_offset + 0x08 > image.len() {
        bail!("image too small for superblock checksum");
    }

    let blkszbits = image.as_bytes()[sb_offset + 0x0C];
    let block_size: u64 = if blkszbits == 0 {
        4096
    } else if blkszbits >= 64 {
        u64::MAX
    } else {
        1u64 << blkszbits
    };

    // Copy the checksum region, zero the checksum field, and compute CRC-32C.
    // When block_size is invalid (<= sb_offset) we mimic Python's behaviour:
    // the slice is empty and the checksum field assignment yields four zero
    // bytes, so the CRC is computed over b"\x00\x00\x00\x00".
    let mut check_data = if block_size > sb_offset as u64 {
        let end = (block_size as usize).min(image.len());
        image.as_bytes()[sb_offset..end].to_vec()
    } else {
        Vec::new()
    };

    // Zero the checksum field (bytes 4-7 of the superblock). If the buffer
    // is shorter than 8 bytes we extend it first, keeping the original prefix.
    if check_data.len() < 8 {
        let prefix = check_data[..check_data.len().min(4)].to_vec();
        check_data.resize(8, 0);
        check_data[..prefix.len()].copy_from_slice(&prefix);
    }
    check_data[4..8].copy_from_slice(&[0, 0, 0, 0]);
    let new_checksum = crc32c(0xFFFFFFFF, &check_data);

    let old_checksum = image.read_field(sb_offset + 0x04, crate::image::FieldWidth::U32)? as u32;
    image.write_field(
        sb_offset + 0x04,
        crate::image::FieldWidth::U32,
        new_checksum as u64,
    )?;

    Ok((old_checksum, new_checksum))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crc32c_known() {
        // Raw CRC-32C for "123456789" with init=~0, no final XOR.
        assert_eq!(crc32c(0xFFFFFFFF, b"123456789"), 486108540);
    }
}
