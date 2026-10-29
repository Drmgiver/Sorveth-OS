//! M2-K.1d: read-only audit of mappings needed by a future independent CR3.
//!
//! This does not create page tables, change CR3, or declare firmware
//! supervisor mappings independent. Bootstrap walks still require the
//! inherited identity map for validating each lower-level table frame.

#[cfg(target_arch = "x86_64")]
use core::arch::asm;

const PAGE: u64 = 4096;
const ADDRESS_MASK: u64 = 0x000f_ffff_ffff_f000;
const PRESENT: u64 = 1;
const WRITE: u64 = 2;
const USER: u64 = 4;
const HUGE: u64 = 1 << 7;
const NX: u64 = 1 << 63;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuditError {
    InvalidAddress,
    MissingTable,
    MissingMapping,
    InvalidHugePage,
    UserAccessible,
    ReadOnlyStack,
    NonExecutableCode,
    UnexpectedCpuRoot,
    InvalidDescriptorTable,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Page {
    pub physical_address: u64,
    pub writable: bool,
    pub executable: bool,
    pub user_accessible: bool,
    pub leaf_size: u64,
}

fn canonical_48(address: u64) -> bool {
    address < 0x0000_8000_0000_0000 || address >= 0xffff_8000_0000_0000
}

/// Pure four-level x86 page walk. The provided reader owns ALL physical
/// access policy; an entry's physical address never becomes a Rust pointer.
/// Handles inherited 1-GiB/2-MiB leaves as well as normal 4-KiB leaves.
pub fn walk(
    root: u64,
    virtual_address: u64,
    mut read: impl FnMut(u64) -> Option<u64>,
) -> Result<Page, AuditError> {
    if root == 0
        || root & (PAGE - 1) != 0
        || root & !ADDRESS_MASK != 0
        || !canonical_48(virtual_address)
    {
        return Err(AuditError::InvalidAddress);
    }
    let mut table = root;
    let mut writable = true;
    let mut executable = true;
    let mut user_accessible = true;
    for shift in [39u32, 30, 21, 12] {
        let index = (virtual_address >> shift) & 511;
        let address = table
            .checked_add(index * 8)
            .ok_or(AuditError::InvalidAddress)?;
        let entry = read(address).ok_or(AuditError::MissingTable)?;
        if entry & PRESENT == 0 {
            return Err(AuditError::MissingMapping);
        }
        writable &= entry & WRITE != 0;
        executable &= entry & NX == 0;
        user_accessible &= entry & USER != 0;
        let huge = entry & HUGE != 0 && shift != 12;
        if huge && shift == 39 {
            return Err(AuditError::InvalidHugePage);
        }
        if huge || shift == 12 {
            let page_bytes = 1u64 << shift;
            let base = entry & ADDRESS_MASK;
            if base & (page_bytes - 1) != 0 {
                return Err(AuditError::InvalidHugePage);
            }
            return Ok(Page {
                physical_address: base + (virtual_address & (page_bytes - 1)),
                writable,
                executable,
                user_accessible,
                leaf_size: page_bytes,
            });
        }
        table = entry & ADDRESS_MASK;
        if table == 0 {
            return Err(AuditError::MissingTable);
        }
    }
    Err(AuditError::MissingMapping)
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Summary {
    pub inspected_pages: u64,
    pub huge_leaf_pages: u64,
    /// Diagnostic only: OVMF can still expose legacy writable+executable
    /// kernel mappings, which MUST be eliminated before K.1d completion.
    pub legacy_write_execute_pages: u64,
}

#[cfg(target_arch = "x86_64")]
#[repr(C, packed)]
#[derive(Clone, Copy)]
struct TableDescriptor {
    limit: u16,
    base: u64,
}

#[cfg(target_arch = "x86_64")]
unsafe fn audit_one(
    root: u64,
    virtual_address: u64,
    need_write: bool,
    need_execute: bool,
    summary: &mut Summary,
) -> Result<(), AuditError> {
    let leaf = walk(root, virtual_address, |entry| {
        crate::root::read_bootstrap_supervisor_entry(entry)
    })?;
    if leaf.user_accessible {
        return Err(AuditError::UserAccessible);
    }
    if need_write && !leaf.writable {
        return Err(AuditError::ReadOnlyStack);
    }
    if need_execute && !leaf.executable {
        return Err(AuditError::NonExecutableCode);
    }
    summary.inspected_pages += 1;
    if leaf.leaf_size != PAGE {
        summary.huge_leaf_pages += 1;
    }
    if leaf.writable && leaf.executable {
        summary.legacy_write_execute_pages += 1;
    }
    Ok(())
}

#[cfg(target_arch = "x86_64")]
unsafe fn audit_range(
    root: u64,
    start: u64,
    end: u64,
    needs_write: bool,
    report: &mut Summary,
) -> Result<(), AuditError> {
    if start == 0 || end <= start || !canonical_48(end - 1) {
        return Err(AuditError::InvalidAddress);
    }
    let mut address = start & !(PAGE - 1);
    let last = (end - 1) & !(PAGE - 1);
    loop {
        audit_one(root, address, needs_write, false, report)?;
        if address == last {
            break;
        }
        address = address.checked_add(PAGE).ok_or(AuditError::InvalidAddress)?;
    }
    Ok(())
}

/// Audit CPU descriptor tables, executable fault paths and all pages of
/// current/kernel worker/IST stacks. No write to live page tables occurs.
///
/// # Safety
/// One QEMU bootstrap CPU at CPL0 with IF=0 and kernel CR3 active. The
/// firmware identity map must still cover inherited paging-table frames.
#[cfg(target_arch = "x86_64")]
pub unsafe fn verify_bootstrap_survival(
    kernel_stack_start: u64,
    kernel_stack_end: u64,
) -> Result<Summary, AuditError> {
    let root = crate::root::kernel_root_physical().ok_or(AuditError::UnexpectedCpuRoot)?;
    let actual_root: u64;
    let rsp: u64;
    let flags: u64;
    asm!("mov {}, cr3", out(reg) actual_root, options(nomem, nostack, preserves_flags));
    asm!("mov {}, rsp", out(reg) rsp, options(nomem, nostack, preserves_flags));
    asm!("pushfq", "pop {}", out(reg) flags, options(preserves_flags));
    if actual_root & ADDRESS_MASK != root || flags & (1 << 9) != 0 {
        return Err(AuditError::UnexpectedCpuRoot);
    }

    let mut idt = TableDescriptor { limit: 0, base: 0 };
    let mut gdt = TableDescriptor { limit: 0, base: 0 };
    asm!("sidt [{}]", in(reg) &mut idt, options(nostack, preserves_flags));
    asm!("sgdt [{}]", in(reg) &mut gdt, options(nostack, preserves_flags));
    let idt_base = idt.base;
    let idt_bytes = idt.limit as u64 + 1;
    let gdt_base = gdt.base;
    let gdt_bytes = gdt.limit as u64 + 1;
    if idt_base == 0 || gdt_base == 0 || idt_bytes < 16 || idt_bytes > 4096
        || gdt_bytes < 24 || gdt_bytes > 4096
    {
        return Err(AuditError::InvalidDescriptorTable);
    }
    let mut report = Summary::default();
    for code in [
        verify_bootstrap_survival as usize as u64,
        crate::serial::write_line as usize as u64,
        crate::root::active as usize as u64,
    ] {
        audit_one(root, code, false, true, &mut report)?;
    }
    for handler in crate::interrupts::survival_handler_addresses() {
        audit_one(root, handler, false, true, &mut report)?;
    }
    // The CPU can call into any of these after a root switch. Audit all
    // pages of stacks, not only their first and last bytes.
    audit_range(root, kernel_stack_start, kernel_stack_end, true, &mut report)?;
    audit_one(root, rsp, true, false, &mut report)?;
    let (worker_start, worker_end) = crate::fibers::survival_stack_bounds();
    audit_range(root, worker_start, worker_end, true, &mut report)?;
    let (fault_stacks, trap_stack) = crate::tss::survival_stack_bounds();
    for (start, end) in fault_stacks {
        audit_range(root, start, end, true, &mut report)?;
    }
    if let Some((start, end)) = trap_stack {
        audit_range(root, start, end, true, &mut report)?;
    }
    audit_range(root, idt_base, idt_base + idt_bytes, true, &mut report)?;
    audit_range(root, gdt_base, gdt_base + gdt_bytes, true, &mut report)?;
    audit_one(root, crate::tss::survival_tss_address(), true, false, &mut report)?;
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_missing_and_user_accessible_paths() {
        let v = 0x8000u64;
        let read = |phys| match phys {
            0x1000 => Some(0x2003),
            0x2000 => Some(0x3003),
            0x3000 => Some(0x4003),
            0x4040 => Some(0x9003),
            _ => None,
        };
        assert_eq!(walk(0x1000, v, read).unwrap().physical_address, 0x9000);
        let user = |phys| match phys {
            0x1000 => Some(0x2007),
            0x2000 => Some(0x3007),
            0x3000 => Some(0x4007),
            0x4040 => Some(0x9007),
            _ => None,
        };
        assert!(walk(0x1000, v, user).unwrap().user_accessible);
        assert_eq!(walk(0x1000, v, |_| None), Err(AuditError::MissingTable));
        assert_eq!(walk(0x1000, v, |_| Some(0)), Err(AuditError::MissingMapping));
    }

    #[test]
    fn supports_aligned_huge_leaves_and_rejects_misaligned() {
        let page = walk(0x1000, 0x12345, |p| match p {
            0x1000 => Some(0x2003),
            0x2000 => Some(0x3003),
            0x3000 => Some(0x20_0083),
            _ => None,
        }).unwrap();
        assert_eq!(page.leaf_size, 2 * 1024 * 1024);
        assert_eq!(page.physical_address, 0x20_0000 + 0x12345);
        assert_eq!(walk(0x1000, 0x12345, |p| match p {
            0x1000 => Some(0x2003),
            0x2000 => Some(0x3003),
            0x3000 => Some(0x21_0083),
            _ => None,
        }), Err(AuditError::InvalidHugePage));
    }

    #[test]
    fn honors_ancestor_writable_executable_and_canonical_policy() {
        let page = walk(0x1000, 0x8000, |phys| match phys {
            0x1000 => Some(0x2001),
            0x2000 => Some(0x3003 | NX),
            0x3000 => Some(0x4003),
            0x4040 => Some(0x9003),
            _ => None,
        }).unwrap();
        assert!(!page.writable);
        assert!(!page.executable);
        assert!(!page.user_accessible);
        assert_eq!(walk(0, 0x8000, |_| None), Err(AuditError::InvalidAddress));
        assert_eq!(walk(0x1000, 0x0000_8000_0000_0000, |_| None), Err(AuditError::InvalidAddress));
    }
}
