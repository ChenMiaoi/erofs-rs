mod engine;
mod fields;
mod grammar;
mod manifest;
mod targets;

use crate::cli::MutateArgs;
use crate::image::read_image;
use anyhow::{Result, bail};
use engine::sha256_hex;
use grammar::mutate_grammar;
use manifest::write_manifest;
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use targets::{
    mutate_chunks, mutate_compressions, mutate_cross_fields, mutate_devices, mutate_dirents,
    mutate_fragments, mutate_inodes, mutate_superblock, mutate_xattrs,
};

pub fn run(args: &MutateArgs) -> Result<()> {
    if !Path::new(&args.input).exists() {
        bail!("Input file not found: {}", args.input);
    }

    fs::create_dir_all(&args.output_dir)
        .map_err(|e| anyhow::anyhow!("failed to create output directory: {e}"))?;

    let image = read_image(&args.input)?;
    let input_sha256 = sha256_hex(&image);

    let mut all_entries = Vec::new();

    match args.target.as_str() {
        "superblock" => all_entries.extend(mutate_superblock(&image, args)?),
        "inode" => all_entries.extend(mutate_inodes(&image, args)?),
        "dirent" => all_entries.extend(mutate_dirents(&image, args)?),
        "xattr" => all_entries.extend(mutate_xattrs(&image, args)?),
        "chunk" => all_entries.extend(mutate_chunks(&image, args)?),
        "compression" => all_entries.extend(mutate_compressions(&image, args)?),
        "fragment" => all_entries.extend(mutate_fragments(&image, args)?),
        "device" => all_entries.extend(mutate_devices(&image, args)?),
        "grammar" => all_entries.extend(mutate_grammar(&image, args)?),
        "cross" => all_entries.extend(mutate_cross_fields(&image, args)?),
        "all" => {
            all_entries.extend(mutate_superblock(&image, args)?);
            all_entries.extend(mutate_inodes(&image, args)?);
            all_entries.extend(mutate_dirents(&image, args)?);
            all_entries.extend(mutate_xattrs(&image, args)?);
            all_entries.extend(mutate_chunks(&image, args)?);
            all_entries.extend(mutate_compressions(&image, args)?);
            all_entries.extend(mutate_fragments(&image, args)?);
            all_entries.extend(mutate_devices(&image, args)?);
            all_entries.extend(mutate_grammar(&image, args)?);
            all_entries.extend(mutate_cross_fields(&image, args)?);
        }
        _ => bail!(
            "unknown mutation target: {} (expected superblock|inode|dirent|xattr|chunk|compression|fragment|device|grammar|cross|all)",
            args.target
        ),
    }

    write_manifest(&args.manifest, args, &all_entries, &input_sha256)?;

    println!(
        "\nDone. Generated {} mutations in {}",
        all_entries.len(),
        args.output_dir
    );
    let mut counts: HashMap<String, usize> = HashMap::new();
    for e in &all_entries {
        *counts.entry(e.classification.clone()).or_insert(0) += 1;
    }
    for (k, v) in {
        let mut items: Vec<_> = counts.iter().collect();
        items.sort_by(|a, b| a.0.cmp(b.0));
        items
    } {
        println!("  {k}: {v}");
    }
    println!("  Manifest: {}", args.manifest);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::engine::mutation_metadata;
    use super::fields::SUPERBLOCK_FIELDS;
    use super::grammar::GRAMMAR_COVERAGE_MODEL;

    #[test]
    fn superblock_mutations_cover_late_format_fields() {
        let names: Vec<_> = SUPERBLOCK_FIELDS
            .iter()
            .map(|field| field.field_name)
            .collect();

        for expected in [
            "epoch",
            "fixed_nsec",
            "uuid_lo",
            "uuid_hi",
            "volume_name_lo",
            "volume_name_hi",
            "feature_incompat",
            "available_compr_algs",
            "extra_devices",
            "devt_slotoff",
            "dirblkbits",
            "xattr_prefix_count",
            "xattr_prefix_start",
            "packed_nid",
            "xattr_filter_reserved",
            "ishare_xattr_prefix_id",
            "reserved",
            "build_time",
            "root_nid_8b",
            "reserved2",
            "metabox_nid",
            "reserved3",
        ] {
            assert!(names.contains(&expected), "missing {expected}");
        }
    }

    #[test]
    fn mutation_metadata_classifies_manifest_rows() {
        assert_eq!(
            mutation_metadata(true, "strict_accepted_tolerant_clean", "accepted"),
            ("grammar_preserving", "checksum_repaired")
        );
        assert_eq!(
            mutation_metadata(false, "strict_accepted_tolerant_clean", "rejected_checksum"),
            ("checksum_invalid", "checksum_raw")
        );
        assert_eq!(
            mutation_metadata(true, "strict_accepted_tolerant_clean", "rejected_invalid"),
            ("semantic_invalid", "checksum_repaired")
        );
        assert_eq!(
            mutation_metadata(true, "strict_rejected_tolerant_errors", "rejected_invalid"),
            ("grammar_invalid", "checksum_repaired")
        );
        assert_eq!(
            mutation_metadata(true, "strict_accepted_tolerant_clean", "sanitizer_crash"),
            ("unsafe_userspace", "checksum_repaired")
        );
    }

    #[test]
    fn grammar_model_covers_deep_semantic_areas() {
        let cases: Vec<_> = GRAMMAR_COVERAGE_MODEL
            .iter()
            .map(|case| case.case_name)
            .collect();
        for expected in [
            "xattr_shared_area_valid",
            "xattr_shared_area_overrun",
            "xattr_long_prefix_entry",
            "xattr_filter_enabled",
            "xattr_filter_reserved_nonzero",
            "packed_fragment_featured",
            "packed_fragment_without_feature",
            "device_table_semantic",
            "device_table_slot_overrun",
            "compressed_layout_compact",
            "compressed_layout_big_pcluster_pair",
            "compressed_layout_reserved_clusterbits",
        ] {
            assert!(cases.contains(&expected), "missing {expected}");
        }

        let features: Vec<_> = GRAMMAR_COVERAGE_MODEL
            .iter()
            .map(|case| case.feature)
            .collect();
        for expected in [
            "xattr_shared_area",
            "xattr_long_prefix",
            "xattr_filter",
            "packed_fragments",
            "device_table",
            "compressed_layout",
        ] {
            assert!(features.contains(&expected), "missing {expected}");
        }
    }
}
