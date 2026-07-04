use crate::image::{Image, Superblock};
use crate::inode::{inode_data_offset, inode_file_size, is_directory_inode};
use anyhow::Result;

/// A located directory entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Dirent {
    /// Byte offset of the dirent header.
    pub offset: usize,
    /// Parent inode NID.
    pub parent_nid: u64,
    /// Entry index within the parent directory block.
    pub entry_idx: u32,
    /// Human-readable description.
    pub desc: String,
}

/// Locate directory entries for all directory inodes.
pub fn locate_dirents_in_image(
    image: &Image,
    sb: &Superblock,
    inodes: &[crate::inode::Inode],
) -> Result<Vec<Dirent>> {
    let mut dirents = Vec::new();

    for inode in inodes {
        if !is_directory_inode(image, inode.offset)? {
            continue;
        }

        let data_start = match inode_data_offset(image, sb, inode.offset) {
            Ok(o) => o,
            Err(_) => continue,
        };
        let data = image.as_bytes();
        if data_start
            .checked_add(12)
            .is_none_or(|end| end > data.len())
        {
            continue;
        }
        let i_size = inode_file_size(image, inode.offset)?;
        let available = data.len().saturating_sub(data_start);
        let dir_len = usize::try_from(i_size).unwrap_or(usize::MAX).min(available);
        let block_size = sb.block_size as usize;

        let mut entry_idx = 0u32;
        let mut block_rel = 0usize;
        while block_rel < dir_len {
            let block_start = match data_start.checked_add(block_rel) {
                Some(offset) => offset,
                None => break,
            };
            let maxsize = (dir_len - block_rel).min(block_size);
            if maxsize < 12
                || block_start
                    .checked_add(12)
                    .is_none_or(|end| end > data.len())
            {
                break;
            }

            let nameoff =
                u16::from_le_bytes([data[block_start + 8], data[block_start + 9]]) as usize;
            if nameoff == 0 || nameoff >= block_size || nameoff % 12 != 0 || nameoff > maxsize {
                break;
            }

            let headers_end = match block_start.checked_add(nameoff) {
                Some(end) => end,
                None => break,
            };
            let mut offset = block_start;
            while offset
                .checked_add(12)
                .is_some_and(|end| end <= headers_end && end <= data.len())
            {
                let file_type = data[offset + 10];
                if file_type > 7 {
                    break;
                }
                dirents.push(Dirent {
                    offset,
                    parent_nid: inode.nid,
                    entry_idx,
                    desc: format!("{}_entry{entry_idx}", inode.desc),
                });
                offset += 12;
                entry_idx += 1;
            }

            let Some(next_block) = block_rel.checked_add(block_size) else {
                break;
            };
            block_rel = next_block;
        }
    }

    Ok(dirents)
}
