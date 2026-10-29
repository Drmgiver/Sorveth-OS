//! M2-J.1: allocation-free, purely numeric 48-bit user-address validation.
//! Success does not prove a mapping exists, belongs to the caller, or is
//! readable/writable. No pointers are dereferenced here.
//! A later step must verify page tables and handle concurrent changes.

use crate::{PAGE_BYTES, USER_LIMIT};

/// Maximum size of one subsequent copy operation (64 KiB).
pub const MAX_USER_TRANSFER_BYTES: u64 = 64 * 1024;
/// The first valid user byte is the start of the second 4-KiB page.
pub const MIN_USER_ADDRESS: u64 = PAGE_BYTES;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UserRangeError {
    ZeroLength,
    TooLarge,
    ArithmeticOverflow,
    NullPage,
    OutsideUserSpace,
}

/// Validated half-open numeric interval [start, end_exclusive).
/// Private fields prevent construction without validation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UserRange {
    start: u64,
    end_exclusive: u64,
    first_page: u64,
    last_page: u64,
}

impl UserRange {
    pub const fn start(self) -> u64 {
        self.start
    }

    pub const fn end_exclusive(self) -> u64 {
        self.end_exclusive
    }

    pub const fn len(self) -> u64 {
        self.end_exclusive - self.start
    }

    pub const fn first_page(self) -> u64 {
        self.first_page
    }

    pub const fn last_page(self) -> u64 {
        self.last_page
    }

    pub const fn page_count(self) -> u64 {
        (self.last_page - self.first_page) / PAGE_BYTES + 1
    }
}

/// Validate a byte range under Sorveth's current 4-level x86-64 paging.
/// Reject null-page bytes, oversized/zero-length buffers, integer overflow,
/// and any byte at or above USER_LIMIT. A nonaligned buffer is permitted;
/// a range ending exactly at USER_LIMIT is valid.
/// No mapping, access right, ownership or page stability check occurs.
pub fn validate_user_range(start: u64, len: u64) -> Result<UserRange, UserRangeError> {
    if len == 0 {
        return Err(UserRangeError::ZeroLength);
    }
    if len > MAX_USER_TRANSFER_BYTES {
        return Err(UserRangeError::TooLarge);
    }
    let end_exclusive = start
        .checked_add(len)
        .ok_or(UserRangeError::ArithmeticOverflow)?;
    if start < MIN_USER_ADDRESS {
        return Err(UserRangeError::NullPage);
    }
    if start >= USER_LIMIT || end_exclusive > USER_LIMIT {
        return Err(UserRangeError::OutsideUserSpace);
    }
    let last_byte = end_exclusive - 1;
    Ok(UserRange {
        start,
        end_exclusive,
        first_page: start & !(PAGE_BYTES - 1),
        last_page: last_byte & !(PAGE_BYTES - 1),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_low_and_high_boundary_bytes() {
        let low = validate_user_range(MIN_USER_ADDRESS, 1).unwrap();
        assert_eq!(low.start(), PAGE_BYTES);
        assert_eq!(low.end_exclusive(), PAGE_BYTES + 1);
        assert_eq!(low.page_count(), 1);
        assert_eq!(low.len(), 1);
        let high = validate_user_range(USER_LIMIT - 1, 1).unwrap();
        assert_eq!(high.end_exclusive(), USER_LIMIT);
        assert_eq!(high.first_page(), USER_LIMIT - PAGE_BYTES);
        assert_eq!(high.last_page(), USER_LIMIT - PAGE_BYTES);
        assert_eq!(high.page_count(), 1);
    }

    #[test]
    fn page_span_counts_misaligned_edges() {
        let same = validate_user_range(PAGE_BYTES + 5, PAGE_BYTES - 5).unwrap();
        assert_eq!(same.page_count(), 1);
        let crossing = validate_user_range(PAGE_BYTES + 5, PAGE_BYTES - 4).unwrap();
        assert_eq!(crossing.page_count(), 2);
        assert_eq!(crossing.last_page(), 2 * PAGE_BYTES);
        let max = validate_user_range(0x1001, MAX_USER_TRANSFER_BYTES).unwrap();
        assert_eq!(max.len(), MAX_USER_TRANSFER_BYTES);
        assert_eq!(max.page_count(), 17);
        assert_eq!(max.first_page(), 0x1000);
        assert_eq!(max.last_page(), 0x11000);
    }

    #[test]
    fn no_null_page_even_for_zero_length() {
        for addr in [0, 1, 0xfff] {
            assert_eq!(validate_user_range(addr, 1), Err(UserRangeError::NullPage));
        }
        for addr in [0, PAGE_BYTES, USER_LIMIT, u64::MAX] {
            assert_eq!(validate_user_range(addr, 0), Err(UserRangeError::ZeroLength));
        }
    }

    #[test]
    fn reject_excessive_length_and_wraparound() {
        assert_eq!(
            validate_user_range(PAGE_BYTES, MAX_USER_TRANSFER_BYTES + 1),
            Err(UserRangeError::TooLarge)
        );
        assert_eq!(
            validate_user_range(PAGE_BYTES, u64::MAX),
            Err(UserRangeError::TooLarge)
        );
        assert_eq!(
            validate_user_range(u64::MAX - 3, 8),
            Err(UserRangeError::ArithmeticOverflow)
        );
        assert_eq!(
            validate_user_range(u64::MAX, 1),
            Err(UserRangeError::ArithmeticOverflow)
        );
    }

    #[test]
    fn reject_user_kernel_boundary_crossing_and_holes() {
        for (start, len) in [
            (USER_LIMIT - 1, 2),
            (USER_LIMIT, 1),
            (USER_LIMIT + 1, 1),
            (0xffff_7fff_ffff_ffff, 1),
            (0xffff_8000_0000_0000, 1),
            (0xffff_ffff_ffff_f000, 1),
        ] {
            assert_eq!(
                validate_user_range(start, len),
                Err(UserRangeError::OutsideUserSpace)
            );
        }
    }

    #[test]
    fn checked_ranges_obey_page_and_byte_invariants() {
        let starts = [
            MIN_USER_ADDRESS,
            MIN_USER_ADDRESS + 1,
            MIN_USER_ADDRESS + PAGE_BYTES - 1,
            MIN_USER_ADDRESS + PAGE_BYTES,
            USER_LIMIT - MAX_USER_TRANSFER_BYTES,
            USER_LIMIT - 1,
        ];
        let lengths = [1, 2, 4095, 4096, 4097, 8192, MAX_USER_TRANSFER_BYTES];
        for start in starts {
            for len in lengths {
                if let Ok(range) = validate_user_range(start, len) {
                    assert_eq!(range.start(), start);
                    assert_eq!(range.len(), len);
                    assert!(range.start() >= MIN_USER_ADDRESS);
                    assert!(range.end_exclusive() <= USER_LIMIT);
                    assert!(range.first_page() <= range.start());
                    assert!(range.last_page() + PAGE_BYTES >= range.end_exclusive());
                    assert!((1..=17).contains(&range.page_count()));
                }
            }
        }
    }
}
