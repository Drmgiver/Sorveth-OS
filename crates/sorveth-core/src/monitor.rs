//! Sorveth bootstrap monitor: a polling, allocation-free kernel diagnostic CLI.
//! NOT a userspace shell or a replacement for process isolation.

use crate::{halt_forever, root, serial};
use sorveth_frames::FramePool;
use sorveth_memory::MapSummary;

const INPUT_LIMIT: usize = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Command {
    Help,
    Status,
    Memory,
    Paging,
    Capabilities,
    Halt,
    Unknown,
    TooLong,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Event {
    Nothing,
    Echo(u8),
    Erase,
    Bell,
    Submit(Command),
}

struct LineEditor {
    bytes: [u8; INPUT_LIMIT],
    length: usize,
    discard: bool,
    ignore_lf: bool,
}

impl LineEditor {
    const fn new() -> Self {
        Self {
            bytes: [0; INPUT_LIMIT],
            length: 0,
            discard: false,
            ignore_lf: false,
        }
    }

    fn feed(&mut self, byte: u8) -> Event {
        if byte == b'\n' && self.ignore_lf {
            self.ignore_lf = false;
            return Event::Nothing;
        }
        self.ignore_lf = byte == b'\r';
        match byte {
            b'\r' | b'\n' => {
                let command = if self.discard {
                    Command::TooLong
                } else {
                    parse(&self.bytes[..self.length])
                };
                self.length = 0;
                self.discard = false;
                Event::Submit(command)
            }
            0x08 | 0x7f => {
                if self.discard {
                    return Event::Nothing;
                }
                if self.length > 0 {
                    self.length -= 1;
                    Event::Erase
                } else {
                    Event::Nothing
                }
            }
            0x20..=0x7e => {
                if self.discard {
                    return Event::Nothing;
                }
                if self.length == INPUT_LIMIT {
                    self.discard = true;
                    return Event::Bell;
                }
                self.bytes[self.length] = byte;
                self.length += 1;
                Event::Echo(byte)
            }
            _ => Event::Nothing,
        }
    }
}

fn parse(bytes: &[u8]) -> Command {
    let line = match core::str::from_utf8(bytes) {
        Ok(line) => line.trim(),
        Err(_) => return Command::Unknown,
    };
    if line.eq_ignore_ascii_case("help") || line == "?" {
        Command::Help
    } else if line.eq_ignore_ascii_case("status") {
        Command::Status
    } else if line.eq_ignore_ascii_case("memory") {
        Command::Memory
    } else if line.eq_ignore_ascii_case("paging") {
        Command::Paging
    } else if line.eq_ignore_ascii_case("caps") {
        Command::Capabilities
    } else if line.eq_ignore_ascii_case("halt") {
        Command::Halt
    } else {
        Command::Unknown
    }
}

fn prompt() {
    serial::write("sorveth> ");
}

fn execute(command: Command, memory: MapSummary, pool: &FramePool<256>) {
    match command {
        Command::Help => serial::write_line("Commands: help status memory paging caps halt"),
        Command::Status => {
            serial::write_line("Kernel: bootstrap monitor; no userspace or scheduler");
            serial::write_line("Firmware boot services: exited");
            serial::write_line("Native serial console: online");
            serial::write_line("IPC: kernel prototype only; user processes pending");
        }
        Command::Memory => {
            serial::write("Memory descriptors: ");
            serial::write_u64(memory.descriptors as u64);
            serial::write_line("");
            serial::write("Conventional pages at boot: ");
            serial::write_u64(memory.conventional_pages);
            serial::write_line("");
            serial::write("Unclaimed planner pages: ");
            match pool.status() {
                Ok(status) => serial::write_u64(status.available_pages),
                Err(_) => serial::write("UNAVAILABLE"),
            }
            serial::write_line("");
            serial::write_line("Claims remain unmapped; lower page tables are inherited");
        }
        Command::Paging => {
            if root::active() {
                serial::write_line("Page table root: Sorveth PML4 active");
                serial::write_line("Lower mappings: mostly inherited (not isolated)");
                serial::write_line("Private supervisor NX scratch mapping: verified");
                serial::write("Sorveth private mapped pages: ");
                serial::write_u64(root::private_pages());
                serial::write_line("");
            } else {
                serial::write_line("Page table root: not installed");
            }
        }
        Command::Capabilities => {
            serial::write_line("Capability table: initialized; no isolated tasks yet");
        }
        Command::Halt => {
            serial::write_line("Kernel halted by monitor command");
            halt_forever();
        }
        Command::Unknown => serial::write_line("Unknown command; enter help"),
        Command::TooLong => serial::write_line("Input too long; command discarded"),
    }
}

/// Owns COM1 while no userspace service exists; busy-polling is temporary.
pub fn run(memory: MapSummary, pool: &FramePool<256>) -> ! {
    let mut editor = LineEditor::new();
    serial::write_line("Sorveth bootstrap monitor v0.1");
    serial::write_line("Type help for available commands.");
    prompt();
    loop {
        if let Some(byte) = serial::try_read() {
            match editor.feed(byte) {
                Event::Nothing => {}
                Event::Echo(value) => serial::put(value),
                Event::Erase => serial::write("\x08 \x08"),
                Event::Bell => serial::put(0x07),
                Event::Submit(command) => {
                    serial::write_line("");
                    execute(command, memory, pool);
                    prompt();
                }
            }
        } else {
            core::hint::spin_loop();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn submit(editor: &mut LineEditor, line: &[u8]) -> Command {
        for &byte in line {
            assert!(!matches!(editor.feed(byte), Event::Submit(_)));
        }
        match editor.feed(b'\r') {
            Event::Submit(command) => command,
            _ => panic!("command was not submitted"),
        }
    }

    #[test]
    fn parses_commands_and_rejects_arguments() {
        let mut editor = LineEditor::new();
        assert_eq!(submit(&mut editor, b"HELP"), Command::Help);
        assert_eq!(submit(&mut editor, b" status "), Command::Status);
        assert_eq!(submit(&mut editor, b"memory"), Command::Memory);
        assert_eq!(submit(&mut editor, b"caps"), Command::Capabilities);
        assert_eq!(submit(&mut editor, b"paging"), Command::Paging);
        assert_eq!(submit(&mut editor, b"halt"), Command::Halt);
        assert_eq!(submit(&mut editor, b"memory anything"), Command::Unknown);
    }

    #[test]
    fn backspace_and_crlf_are_handled_once() {
        let mut editor = LineEditor::new();
        assert_eq!(editor.feed(0x08), Event::Nothing);
        for &byte in b"statuz" {
            editor.feed(byte);
        }
        assert_eq!(editor.feed(0x7f), Event::Erase);
        editor.feed(b's');
        assert_eq!(editor.feed(b'\r'), Event::Submit(Command::Status));
        assert_eq!(editor.feed(b'\n'), Event::Nothing);
    }

    #[test]
    fn overlong_input_is_discarded_not_executed() {
        let mut editor = LineEditor::new();
        for _ in 0..INPUT_LIMIT {
            assert_eq!(editor.feed(b'x'), Event::Echo(b'x'));
        }
        assert_eq!(editor.feed(b'y'), Event::Bell);
        assert_eq!(editor.feed(b'\r'), Event::Submit(Command::TooLong));
        assert_eq!(submit(&mut editor, b"help"), Command::Help);
    }

    #[test]
    fn ignores_control_bytes_and_supports_lf_only() {
        let mut editor = LineEditor::new();
        assert_eq!(editor.feed(0), Event::Nothing);
        assert_eq!(editor.feed(0x1b), Event::Nothing);
        for &byte in b"help" {
            editor.feed(byte);
        }
        assert_eq!(editor.feed(b'\n'), Event::Submit(Command::Help));
    }
}
