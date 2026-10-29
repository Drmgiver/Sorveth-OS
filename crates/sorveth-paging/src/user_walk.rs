//! M2-J.2: bounded, read-only 4-level x86-64 user page-table walking.
//!
//! This code consumes a range already validated by M2-J.1 and reads
//! page-table words through a *trusted physical-entry reader* supplied by
//! privileged kernel code. The reader must not dereference arbitrary
//! attacker-controlled physical addresses: it must restrict reads to owned,
//! mapped page-table frames. No user pointers or physical frames are read
//! or written by this module.
//!
//! This is a snapshot, not a pinned mapping or an authorization to copy.
//! J.3/J.4 must prevent page-table replacement/reclamation during copying.

use crate::{
    user_range::{UserRange, MAX_USER_TRANSFER_BYTES},
    PAGE_BYTES,
};

const ADDRESS_MASK: u64 = 0x000f_ffff_ffff_f000;
const PRESENT: u64 = 1;
const WRITABLE: u64 = 1 << 1;
const USER: u64 = 1 << 2;
const LARGE_PAGE: u64 = 1 << 7;
pub const MAX_RESOLVED_PAGES: usize = (MAX_USER_TRANSFER_BYTES / PAGE_BYTES + 1) as usize;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UserAccess {
    Read,
    Write,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WalkError {
    InvalidRoot,
    TableNotOwned,
    MissingMapping,
    PermissionDenied,
    UnsupportedLargePage,
    InvalidPhysicalFrame,
}

/// A complete snapshot of physical 4 KiB pages for a bounded validated
/// virtual range. Private fields prevent fabrication of a successful walk.
/// The snapshot does not pin frames or authorize subsequent dereferencing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResolvedPages {
    pages: [u64; MAX_RESOLVED_PAGES],
    count: u8,
}

impl ResolvedPages {
    pub fn page_count(&self) -> usize {
        self.count as usize
    }

    pub fn physical_page(&self, index: usize) -> Option<u64> {
        if index < self.page_count() {
            Some(self.pages[index])
        } else {
            None
        }
    }
}

/// Resolve *every* page of a validated user range using the selected
/// process's kernel-owned PML4. At each level the hardware U/S and R/W
/// permissions are checked; a write requires writable bits at every level.
/// Unmapped entries and inaccessible tables fail closed. 1-GiB and 2-MiB
/// mappings are not yet supported and are rejected, never reinterpreted.
///
/// The callback takes the **physical address of a 64-bit table entry**.
/// It must only read a verified page-table frame that the kernel owns and
/// has safely mapped. In particular, do not directly dereference a
/// physical pointer derived from an unchecked PTE.
///
/// The returned physical pages are a point-in-time observation. Concurrent
/// table changes, frame reclamation and safe copy-in/out are *not* covered.
pub fn walk_user_pages(
    root: u64,
    range: UserRange,
    access: UserAccess,
    mut read_entry: impl FnMut(u64) -> Option<u64>,
) -> Result<ResolvedPages, WalkError> {
    if root == 0 || root & (PAGE_BYTES - 1) != 0 || root & !ADDRESS_MASK != 0 {
        return Err(WalkError::InvalidRoot);
    }
    let count = range.page_count() as usize;
    if count == 0 || count > MAX_RESOLVED_PAGES {
        return Err(WalkError::InvalidPhysicalFrame);
    }
    let mut result = ResolvedPages {
        pages: [0; MAX_RESOLVED_PAGES],
        count: 0,
    };
    for index in 0..count {
        let virtual_page = range.first_page() + (index as u64) * PAGE_BYTES;
        let mut table = root;
        for (level, shift) in [39u32, 30, 21, 12].iter().enumerate() {
            let slot = (virtual_page >> shift) & 0x1ff;
            let entry_address = table + slot * 8;
            let entry = read_entry(entry_address).ok_or(WalkError::TableNotOwned)?;
            if entry & PRESENT == 0 {
                return Err(WalkError::MissingMapping);
            }
            if entry & USER == 0 || (access == UserAccess::Write && entry & WRITABLE == 0) {
                return Err(WalkError::PermissionDenied);
            }
            // At upper PDPT/PD levels, PS changes physical-address
            // interpretation. A leaf PTE bit 7 is PAT, not PS.
            if (level == 1 || level == 2) && entry & LARGE_PAGE != 0 {
                return Err(WalkError::UnsupportedLargePage);
            }
            let physical = entry & ADDRESS_MASK;
            if physical == 0 {
                return Err(WalkError::InvalidPhysicalFrame);
            }
            table = physical;
        }
        result.pages[index] = table;
    }
    result.count = count as u8;
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::user_range::validate_user_range;

    const NX: u64 = 1 << 63;
    const ROOT: u64 = 0x1000;
    const VA: u64 = 0x4000;

    // PML4 -> PDPT -> PD -> PT -> two adjacent 4-KiB leaves.
    fn sample() -> [(u64, u64); 5] {
        [
            (0x1000, 0x2000 | PRESENT | WRITABLE | USER),
            (0x2000, 0x3000 | PRESENT | WRITABLE | USER),
            (0x3000, 0x4000 | PRESENT | WRITABLE | USER),
            (0x4000 + 4 * 8, 0x9000 | PRESENT | WRITABLE | USER | NX),
            (0x4000 + 5 * 8, 0xa000 | PRESENT | WRITABLE | USER | NX),
        ]
    }

    fn read(map: &[(u64, u64)], address: u64) -> Option<u64> {
        map.iter().find(|(at, _)| *at == address).map(|(_, v)| *v)
    }

    #[test]
    fn walk_reads_all_pages_and_preserves_noncontiguous_physical_frames() {
        let mut map = sample();
        map[4].1 = 0xd000 | PRESENT | WRITABLE | USER | NX;
        let range = validate_user_range(VA + PAGE_BYTES - 1, 2).unwrap();
        let resolved = walk_user_pages(ROOT, range, UserAccess::Read, |at| read(&map, at)).unwrap();
        assert_eq!(resolved.page_count(), 2);
        assert_eq!(resolved.physical_page(0), Some(0x9000));
        assert_eq!(resolved.physical_page(1), Some(0xd000));
        assert_eq!(resolved.physical_page(2), None);
    }

    #[test]
    fn write_allowed_only_if_every_paging_level_is_writable() {
        let initial = sample();
        let range = validate_user_range(VA, 8).unwrap();
        assert!(walk_user_pages(ROOT, range, UserAccess::Write, |at| read(&initial, at)).is_ok());
        for i in 0..5 {
            let mut map = initial;
            map[i].1 &= !WRITABLE;
            let one = if i == 4 {
                validate_user_range(VA + PAGE_BYTES, 8).unwrap()
            } else {
                range
            };
            assert_eq!(
                walk_user_pages(ROOT, one, UserAccess::Write, |at| read(&map, at)),
                Err(WalkError::PermissionDenied)
            );
            // Read access must not be incorrectly rejected for read-only data.
            assert!(walk_user_pages(ROOT, one, UserAccess::Read, |at| read(&map, at)).is_ok());
        }
    }

    #[test]
    fn rejects_nonuser_ancestors_and_leaf_even_for_read() {
        let original = sample();
        let range = validate_user_range(VA, 8).unwrap();
        for i in 0..4 {
            let mut map = original;
            map[i].1 &= !USER;
            assert_eq!(
                walk_user_pages(ROOT, range, UserAccess::Read, |at| read(&map, at)),
                Err(WalkError::PermissionDenied)
            );
        }
    }

    #[test]
    fn rejects_unmapped_page_even_after_first_page_passes() {
        let mut map = sample();
        map[4].1 = 0;
        let across = validate_user_range(VA + PAGE_BYTES - 1, 2).unwrap();
        assert_eq!(
            walk_user_pages(ROOT, across, UserAccess::Read, |at| read(&map, at)),
            Err(WalkError::MissingMapping)
        );
        // The physical reader only sees page-table entries it explicitly
        // admits; an unowned table is not dereferenced.
        assert_eq!(
            walk_user_pages(ROOT, across, UserAccess::Read, |at| {
                if at == 0x3000 {
                    None
                } else {
                    read(&sample(), at)
                }
            }),
            Err(WalkError::TableNotOwned)
        );
    }

    #[test]
    fn rejects_huge_pages_zero_frames_and_invalid_root() {
        let range = validate_user_range(VA, 4).unwrap();
        for root in [0, 1, ROOT + 1, 1 << 63] {
            assert_eq!(
                walk_user_pages(root, range, UserAccess::Read, |_| Some(0)),
                Err(WalkError::InvalidRoot)
            );
        }
        for level in [1, 2] {
            let mut map = sample();
            map[level].1 |= LARGE_PAGE;
            assert_eq!(
                walk_user_pages(ROOT, range, UserAccess::Read, |at| read(&map, at)),
                Err(WalkError::UnsupportedLargePage)
            );
        }
        let mut map = sample();
        map[3].1 &= !ADDRESS_MASK;
        assert_eq!(
            walk_user_pages(ROOT, range, UserAccess::Read, |at| read(&map, at)),
            Err(WalkError::InvalidPhysicalFrame)
        );
    }

    #[test]
    fn accessed_dirty_and_nx_do_not_deny_data_reads() {
        let mut map = sample();
        for entry in &mut map {
            entry.1 |= 1 << 5;
        }
        map[3].1 |= 1 << 6;
        let range = validate_user_range(VA, 1).unwrap();
        assert_eq!(
            walk_user_pages(ROOT, range, UserAccess::Read, |at| read(&map, at))
                .unwrap()
                .physical_page(0),
            Some(0x9000)
        );
    }

    #[test]
    fn distinct_roots_do_not_imply_shared_user_mapping() {
        let map = sample();
        let range = validate_user_range(VA, 8).unwrap();
        assert_eq!(
            walk_user_pages(0x7000, range, UserAccess::Read, |at| read(&map, at)),
            Err(WalkError::TableNotOwned)
        );
    }
}
