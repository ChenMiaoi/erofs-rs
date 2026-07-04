use crate::checksum::fix_checksum;
use crate::cli::InfoArgs;
use crate::dirent::locate_dirents_in_image;
use crate::image::read_image;
use crate::inode::locate_inodes;
use anyhow::Result;

pub fn run(args: &InfoArgs) -> Result<()> {
    let mut image = read_image(&args.input)?;
    let sb = image.superblock()?;

    println!("Superblock:");
    println!("  magic:          0x{:08X}", sb.magic);
    println!("  checksum:       0x{:08X}", sb.checksum);
    println!("  feature_compat: 0x{:08X}", sb.feature_compat);
    println!("  feature_incompat: 0x{:08X}", sb.feature_incompat);
    println!(
        "  blkszbits:      {} (block_size={})",
        sb.blkszbits, sb.block_size
    );
    println!(
        "  sb_extslots:    {} (sb_size={})",
        sb.sb_extslots, sb.sb_size
    );
    println!("  rootnid:        {}", sb.rootnid);
    println!("  inos:           {}", sb.inos);
    println!("  blocks_lo:      {}", sb.blocks_lo);
    println!("  dirblkbits:     {}", sb.dirblkbits);
    println!(
        "  meta_blkaddr:   0x{:08X} (offset=0x{:X})",
        sb.meta_blkaddr, sb.meta_offset
    );
    println!("  xattr_blkaddr:  0x{:08X}", sb.xattr_blkaddr);

    if args.fix_checksum {
        let (old, new) = fix_checksum(&mut image)?;
        println!("\nChecksum recalculated: 0x{old:08X} -> 0x{new:08X}");
    }

    let inodes = locate_inodes(&image, &sb)?;
    println!("\nInodes ({} found):", inodes.len());
    for inode in &inodes {
        println!(
            "  nid={:>3} offset=0x{:08X} desc={}",
            inode.nid, inode.offset, inode.desc
        );
    }

    let dirents = locate_dirents_in_image(&image, &sb, &inodes)?;
    println!("\nDirectory entries ({} found):", dirents.len());
    for d in &dirents {
        println!(
            "  parent_nid={:>3} entry={:>2} offset=0x{:08X} desc={}",
            d.parent_nid, d.entry_idx, d.offset, d.desc
        );
    }

    Ok(())
}
