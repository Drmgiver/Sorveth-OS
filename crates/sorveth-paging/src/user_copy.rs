//! M2-J.3: allocation-free bounded scatter copy from verified user pages.
//!
//! The caller must ensure process ownership, locked/stable page tables and
//! safe physical mappings for the entire call. The QEMU kernel currently
//! holds two permanently allocated data frames and executes on one core
//! without preemption. This is not yet a general userspace syscall.
//!
//! Validation must complete before any output byte is overwritten.

use crate::{user_range::UserRange, user_walk::ResolvedPages, PAGE_BYTES};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CopyError {
    DestinationLength,
    IncompleteMapping,
    UnownedPhysicalPage,
}

/// Preflight every source page before writing any destination byte.
///
/// The caller-supplied allow_page callback must admit only stable,
/// permanently accessible, calling-process-owned physical data pages;
/// read_bytes must be infallible for these admitted pages. Both callbacks
/// are trusted kernel code, never unprivileged user-provided callbacks.
/// This routine does not dereference raw physical or user pointers.
///
/// On a returned error, the destination is unchanged. An external fault or
/// concurrent unmapping is NOT recoverable: the caller must exclude both.
pub fn copy_from_resolved(
    range: UserRange,
    pages: &ResolvedPages,
    destination: &mut [u8],
    mut allow_page: impl FnMut(u64) -> bool,
    mut read_bytes: impl FnMut(u64, &mut [u8]),
) -> Result<(), CopyError> {
    if destination.len() as u64 != range.len() {
        return Err(CopyError::DestinationLength);
    }
    if pages.page_count() != range.page_count() as usize {
        return Err(CopyError::IncompleteMapping);
    }

    // All-or-nothing permission/ownership preflight.
    for index in 0..pages.page_count() {
        let page = pages
            .physical_page(index)
            .ok_or(CopyError::IncompleteMapping)?;
        if page == 0 || page & (PAGE_BYTES - 1) != 0 || !allow_page(page) {
            return Err(CopyError::UnownedPhysicalPage);
        }
    }

    let mut copied = 0usize;
    let mut page_offset = (range.start() & (PAGE_BYTES - 1)) as usize;
    for index in 0..pages.page_count() {
        let frame = pages
            .physical_page(index)
            .ok_or(CopyError::IncompleteMapping)?;
        let bytes = core::cmp::min(
            destination.len() - copied,
            PAGE_BYTES as usize - page_offset,
        );
        read_bytes(
            frame + page_offset as u64,
            &mut destination[copied..copied + bytes],
        );
        copied += bytes;
        page_offset = 0;
    }
    Ok(())
}

/// Transfer kernel-owned source bytes into prevalidated, process-owned
/// writable user pages. The caller must have walked every destination
/// with UserAccess::Write and must guarantee the mapping and frames stay
/// stable for the entire operation.
///
/// This policy deliberately makes no raw pointer dereferences. Every page
/// is preflighted before write_bytes is invoked, so a returned rejection
/// leaves ALL destination bytes untouched. The kernel-only callbacks must
/// guarantee physical access is infallible after validation; hardware
/// faults and concurrent remapping are not recoverable in this bootstrap.
///
/// The supplied source is trusted, valid kernel memory and must not alias
/// destination physical frames through another virtual mapping.
pub fn copy_to_resolved(
    range: UserRange,
    pages: &ResolvedPages,
    source: &[u8],
    mut allow_page: impl FnMut(u64) -> bool,
    mut write_bytes: impl FnMut(u64, &[u8]),
) -> Result<(), CopyError> {
    if source.len() as u64 != range.len() {
        return Err(CopyError::DestinationLength);
    }
    if pages.page_count() != range.page_count() as usize {
        return Err(CopyError::IncompleteMapping);
    }
    // The complete destination is preflighted; never begin a partial
    // write just because the first of multiple pages is writable.
    for index in 0..pages.page_count() {
        let page = pages
            .physical_page(index)
            .ok_or(CopyError::IncompleteMapping)?;
        if page == 0 || page & (PAGE_BYTES - 1) != 0 || !allow_page(page) {
            return Err(CopyError::UnownedPhysicalPage);
        }
    }

    let mut copied = 0usize;
    let mut page_offset = (range.start() & (PAGE_BYTES - 1)) as usize;
    for index in 0..pages.page_count() {
        let frame = pages
            .physical_page(index)
            .ok_or(CopyError::IncompleteMapping)?;
        let bytes = core::cmp::min(
            source.len() - copied,
            PAGE_BYTES as usize - page_offset,
        );
        write_bytes(
            frame + page_offset as u64,
            &source[copied..copied + bytes],
        );
        copied += bytes;
        page_offset = 0;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        user_range::validate_user_range,
        user_walk::{walk_user_pages, UserAccess},
    };

    const P: u64 = 1;
    const W: u64 = 1 << 1;
    const U: u64 = 1 << 2;

    fn walk(range: UserRange) -> ResolvedPages {
        // Synthetic four-level paging tree with distinct physical leaves.
        walk_user_pages(0x1000, range, UserAccess::Read, |at| {
            Some(match at {
                0x1000 => 0x2000 | P | W | U,
                0x2000 => 0x3000 | P | W | U,
                0x3000 => 0x4000 | P | W | U,
                0x4020 => 0x9000 | P | W | U,
                0x4028 => 0xb000 | P | W | U,
                _ => return None,
            })
        })
        .unwrap()
    }

    #[test]
    fn copies_across_two_noncontiguous_physical_pages() {
        let range = validate_user_range(0x4ffc, 8).unwrap();
        let frames = walk(range);
        let mut destination = [0u8; 8];
        let mut seen = [0u64; 2];
        let mut calls = 0;
        copy_from_resolved(
            range,
            &frames,
            &mut destination,
            |page| page == 0x9000 || page == 0xb000,
            |address, out| {
                seen[calls] = address;
                calls += 1;
                for (i, byte) in out.iter_mut().enumerate() {
                    *byte = (address as u8).wrapping_add(i as u8);
                }
            },
        )
        .unwrap();
        assert_eq!(destination, [0xfc, 0xfd, 0xfe, 0xff, 0, 1, 2, 3]);
        assert_eq!(seen, [0x9ffc, 0xb000]);
        assert_eq!(calls, 2);
    }

    #[test]
    fn unowned_second_page_preserves_every_destination_byte() {
        let range = validate_user_range(0x4fff, 2).unwrap();
        let frames = walk(range);
        let mut destination = [0xa5u8; 2];
        let mut reads = 0;
        assert_eq!(
            copy_from_resolved(
                range,
                &frames,
                &mut destination,
                |page| page == 0x9000,
                |_, _| reads += 1,
            ),
            Err(CopyError::UnownedPhysicalPage)
        );
        assert_eq!(destination, [0xa5; 2]);
        assert_eq!(reads, 0);
    }

    #[test]
    fn incorrect_destination_size_rejects_before_access() {
        let range = validate_user_range(0x4000, 8).unwrap();
        let frames = walk(range);
        let mut destination = [0x6cu8; 7];
        let touched = core::cell::Cell::new(false);
        assert_eq!(
            copy_from_resolved(
                range,
                &frames,
                &mut destination,
                |_| {
                    touched.set(true);
                    true
                },
                |_, _| touched.set(true),
            ),
            Err(CopyError::DestinationLength)
        );
        assert!(!touched.get());
        assert_eq!(destination, [0x6c; 7]);
    }

    #[test]
    fn exactly_last_byte_of_page_does_not_touch_next_page() {
        let range = validate_user_range(0x4fff, 1).unwrap();
        let frames = walk(range);
        let mut destination = [0u8; 1];
        copy_from_resolved(
            range,
            &frames,
            &mut destination,
            |page| page == 0x9000,
            |address, out| {
                assert_eq!(address, 0x9fff);
                out[0] = 0x42;
            },
        )
        .unwrap();
        assert_eq!(destination, [0x42]);
    }

    #[test]
    fn copy_out_handles_misaligned_noncontiguous_physical_pages() {
        let range = validate_user_range(0x4ffd, 7).unwrap();
        let frames = walk(range);
        let source = [1u8, 2, 3, 4, 5, 6, 7];
        let mut calls = 0;
        let mut writes = [(0u64, [0u8; 4]); 2];
        copy_to_resolved(
            range,
            &frames,
            &source,
            |page| page == 0x9000 || page == 0xb000,
            |address, bytes| {
                let i = calls;
                calls += 1;
                writes[i].0 = address;
                writes[i].1[..bytes.len()].copy_from_slice(bytes);
            },
        )
        .unwrap();
        assert_eq!(calls, 2);
        assert_eq!(writes[0], (0x9ffd, [1, 2, 3, 0]));
        assert_eq!(writes[1], (0xb000, [4, 5, 6, 7]));
    }

    #[test]
    fn copy_out_rejected_second_page_never_writes_first_page() {
        let range = validate_user_range(0x4fff, 2).unwrap();
        let frames = walk(range);
        let writes = core::cell::Cell::new(0);
        assert_eq!(
            copy_to_resolved(
                range,
                &frames,
                &[3, 4],
                |page| page == 0x9000,
                |_, _| writes.set(writes.get() + 1),
            ),
            Err(CopyError::UnownedPhysicalPage)
        );
        assert_eq!(writes.get(), 0);
    }

    #[test]
    fn copy_out_rejects_mismatched_source_length_without_page_reads() {
        let range = validate_user_range(0x4000, 8).unwrap();
        let frames = walk(range);
        let touched = core::cell::Cell::new(false);
        assert_eq!(
            copy_to_resolved(
                range,
                &frames,
                &[0u8; 7],
                |_| {
                    touched.set(true);
                    true
                },
                |_, _| touched.set(true),
            ),
            Err(CopyError::DestinationLength)
        );
        assert!(!touched.get());
    }

    #[test]
    fn copy_out_last_byte_of_page_does_not_touch_adjacent_frame() {
        let range = validate_user_range(0x4fff, 1).unwrap();
        let frames = walk(range);
        let mut calls = 0;
        copy_to_resolved(
            range,
            &frames,
            &[0x42],
            |page| page == 0x9000,
            |address, bytes| {
                assert_eq!(address, 0x9fff);
                assert_eq!(bytes, &[0x42]);
                calls += 1;
            },
        )
        .unwrap();
        assert_eq!(calls, 1);
    }

}
