//! M2-K.1d: bounded PE32+ section policy for the UEFI-loaded kernel image.
//!
//! This parses a *validated in-memory header prefix*, not an untrusted
//! filesystem path. It does not write permissions or change live paging.

pub const HEADER_LIMIT: usize = 4096;
pub const MAX_SECTIONS: usize = 32;
const PAGE: u64 = 4096;
const EXECUTE: u32 = 0x2000_0000;
const READ: u32 = 0x4000_0000;
const WRITE: u32 = 0x8000_0000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    InvalidHeaders,
    UnsupportedMachine,
    UnsupportedAlignment,
    InvalidSection,
    SectionOverlap,
    WritableExecutableSection,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PagePolicy {
    Headers,
    Code,
    ReadOnly,
    Writable,
    Unclassified,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Section {
    pub start: u64,
    pub end: u64,
    pub executable: bool,
    pub writable: bool,
}

pub struct Layout {
    image_size: u64,
    header_end: u64,
    sections: [Option<Section>; MAX_SECTIONS],
    count: usize,
}

fn word(bytes: &[u8], at: usize) -> Option<u16> {
    let s = bytes.get(at..at.checked_add(2)?)?;
    Some(u16::from_le_bytes([s[0], s[1]]))
}

fn dword(bytes: &[u8], at: usize) -> Option<u32> {
    let s = bytes.get(at..at.checked_add(4)?)?;
    Some(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

fn page_round(value: u64) -> Option<u64> {
    value.checked_add(PAGE - 1).map(|x| x & !(PAGE - 1))
}

/// Strictly bounded PE32+ AMD64 parser. Reject ambiguous RVA overlap and
/// sections declaring writable+executable memory instead of "fixing" them.
pub fn parse(header: &[u8], allocated_size: u64) -> Result<Layout, Error> {
    if header.len() < 128
        || header.len() > HEADER_LIMIT
        || allocated_size < PAGE
        || allocated_size & (PAGE - 1) != 0
        || word(header, 0) != Some(0x5a4d)
    {
        return Err(Error::InvalidHeaders);
    }
    let pe = dword(header, 0x3c).ok_or(Error::InvalidHeaders)? as usize;
    if pe < 64 || dword(header, pe) != Some(0x0000_4550) {
        return Err(Error::InvalidHeaders);
    }
    if word(header, pe + 4) != Some(0x8664) {
        return Err(Error::UnsupportedMachine);
    }
    let count = word(header, pe + 6).ok_or(Error::InvalidHeaders)? as usize;
    let optional_size = word(header, pe + 20).ok_or(Error::InvalidHeaders)? as usize;
    let optional = pe.checked_add(24).ok_or(Error::InvalidHeaders)?;
    let sections_start = optional
        .checked_add(optional_size)
        .ok_or(Error::InvalidHeaders)?;
    if count == 0 || count > MAX_SECTIONS || optional_size < 64 {
        return Err(Error::InvalidHeaders);
    }
    let table_end = sections_start
        .checked_add(count * 40)
        .ok_or(Error::InvalidHeaders)?;
    if table_end > header.len() || word(header, optional) != Some(0x20b) {
        return Err(Error::InvalidHeaders);
    }
    let alignment = dword(header, optional + 32).ok_or(Error::InvalidHeaders)? as u64;
    if alignment != PAGE {
        return Err(Error::UnsupportedAlignment);
    }
    let image_size = dword(header, optional + 56).ok_or(Error::InvalidHeaders)? as u64;
    let size_headers = dword(header, optional + 60).ok_or(Error::InvalidHeaders)? as u64;
    if image_size != allocated_size || size_headers < table_end as u64 {
        return Err(Error::InvalidHeaders);
    }
    let header_end = page_round(size_headers).ok_or(Error::InvalidHeaders)?;
    if header_end == 0 || header_end > image_size {
        return Err(Error::InvalidHeaders);
    }

    let mut layout = Layout {
        image_size,
        header_end,
        sections: [None; MAX_SECTIONS],
        count,
    };
    for index in 0..count {
        let at = sections_start + index * 40;
        let virtual_size = dword(header, at + 8).ok_or(Error::InvalidSection)? as u64;
        let start = dword(header, at + 12).ok_or(Error::InvalidSection)? as u64;
        let raw_size = dword(header, at + 16).ok_or(Error::InvalidSection)? as u64;
        let flags = dword(header, at + 36).ok_or(Error::InvalidSection)?;
        let bytes = virtual_size.max(raw_size);
        let rounded = page_round(bytes).ok_or(Error::InvalidSection)?;
        let end = start.checked_add(rounded).ok_or(Error::InvalidSection)?;
        if rounded == 0
            || start < header_end
            || start & (PAGE - 1) != 0
            || end > image_size
            || flags & READ == 0
        {
            return Err(Error::InvalidSection);
        }
        let executable = flags & EXECUTE != 0;
        let writable = flags & WRITE != 0;
        if executable && writable {
            return Err(Error::WritableExecutableSection);
        }
        for prior in layout.sections[..index].iter().flatten() {
            if start < prior.end && prior.start < end {
                return Err(Error::SectionOverlap);
            }
        }
        layout.sections[index] = Some(Section {
            start,
            end,
            executable,
            writable,
        });
    }
    Ok(layout)
}

impl Layout {
    pub const fn section_count(&self) -> usize {
        self.count
    }

    pub fn classify(&self, rva: u64) -> PagePolicy {
        if rva >= self.image_size {
            return PagePolicy::Unclassified;
        }
        if rva < self.header_end {
            return PagePolicy::Headers;
        }
        for section in self.sections[..self.count].iter().flatten() {
            if (section.start..section.end).contains(&rva) {
                return if section.executable {
                    PagePolicy::Code
                } else if section.writable {
                    PagePolicy::Writable
                } else {
                    PagePolicy::ReadOnly
                };
            }
        }
        PagePolicy::Unclassified
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SectionEvidence {
    pub section_count: usize,
    pub code_pages: u64,
    pub readonly_pages: u64,
    pub writable_pages: u64,
    /// Gaps have no approved permissions and cannot be mapped by a new CR3.
    pub unclassified_pages: u64,
}

/// Reads only the first page after the complete-image backing scan confirms
/// the inherited identity mapping and retained loader memory.
///
/// # Safety
/// Called only during the single-CPU kernel bootstrap; `boot.image_base`
/// must have passed the physical backing audit immediately beforehand.
#[cfg(target_arch = "x86_64")]
pub unsafe fn verify_loaded_pe_sections(
    boot: &sorveth_abi::BootInfo,
) -> Result<SectionEvidence, Error> {
    if !boot.is_valid() {
        return Err(Error::InvalidHeaders);
    }
    let header = core::slice::from_raw_parts(boot.image_base as *const u8, HEADER_LIMIT);
    let parsed = parse(header, boot.image_size)?;
    let mut proof = SectionEvidence {
        section_count: parsed.section_count(),
        code_pages: 0,
        readonly_pages: 0,
        writable_pages: 0,
        unclassified_pages: 0,
    };
    let mut rva = 0;
    while rva < boot.image_size {
        match parsed.classify(rva) {
            PagePolicy::Headers | PagePolicy::ReadOnly => proof.readonly_pages += 1,
            PagePolicy::Code => proof.code_pages += 1,
            PagePolicy::Writable => proof.writable_pages += 1,
            PagePolicy::Unclassified => proof.unclassified_pages += 1,
        }
        rva += PAGE;
    }
    if proof.code_pages == 0 || proof.writable_pages == 0 {
        return Err(Error::InvalidSection);
    }
    Ok(proof)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> [u8; HEADER_LIMIT] {
        let mut img = [0u8; HEADER_LIMIT];
        img[0..2].copy_from_slice(b"MZ");
        img[0x3c..0x40].copy_from_slice(&(0x80u32).to_le_bytes());
        img[0x80..0x84].copy_from_slice(b"PE\0\0");
        img[0x84..0x86].copy_from_slice(&(0x8664u16).to_le_bytes());
        img[0x86..0x88].copy_from_slice(&(2u16).to_le_bytes());
        img[0x94..0x96].copy_from_slice(&(0xf0u16).to_le_bytes());
        img[0x98..0x9a].copy_from_slice(&(0x20bu16).to_le_bytes());
        img[0xb8..0xbc].copy_from_slice(&(4096u32).to_le_bytes());
        img[0xd0..0xd4].copy_from_slice(&(0x4000u32).to_le_bytes());
        img[0xd4..0xd8].copy_from_slice(&(0x400u32).to_le_bytes());
        let s = 0x188;
        img[s + 8..s + 12].copy_from_slice(&(0x900u32).to_le_bytes());
        img[s + 12..s + 16].copy_from_slice(&(0x1000u32).to_le_bytes());
        img[s + 16..s + 20].copy_from_slice(&(0xa00u32).to_le_bytes());
        img[s + 36..s + 40].copy_from_slice(&(0x6000_0020u32).to_le_bytes());
        let d = s + 40;
        img[d + 8..d + 12].copy_from_slice(&(0x800u32).to_le_bytes());
        img[d + 12..d + 16].copy_from_slice(&(0x2000u32).to_le_bytes());
        img[d + 16..d + 20].copy_from_slice(&(0x600u32).to_le_bytes());
        img[d + 36..d + 40].copy_from_slice(&(0xc000_0040u32).to_le_bytes());
        img
    }

    #[test]
    fn classifies_section_pages_without_guessing_holes() {
        let layout = parse(&sample(), 0x4000).unwrap();
        assert_eq!(layout.section_count(), 2);
        assert_eq!(layout.classify(0), PagePolicy::Headers);
        assert_eq!(layout.classify(0x1000), PagePolicy::Code);
        assert_eq!(layout.classify(0x2000), PagePolicy::Writable);
        assert_eq!(layout.classify(0x3000), PagePolicy::Unclassified);
    }

    #[test]
    fn rejects_wrong_machine_overlaps_and_wx_sections() {
        let mut img = sample();
        img[0x84..0x86].copy_from_slice(&(0x14cu16).to_le_bytes());
        assert!(matches!(
            parse(&img, 0x4000),
            Err(Error::UnsupportedMachine)
        ));
        img = sample();
        img[0x1bc..0x1c0].copy_from_slice(&(0x1000u32).to_le_bytes());
        assert!(matches!(parse(&img, 0x4000), Err(Error::SectionOverlap)));
        img = sample();
        img[0x1ac..0x1b0].copy_from_slice(&(0xe000_0020u32).to_le_bytes());
        assert!(matches!(
            parse(&img, 0x4000),
            Err(Error::WritableExecutableSection)
        ));
    }
}
