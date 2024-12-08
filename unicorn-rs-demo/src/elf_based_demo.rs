use clap::Parser;
use unicorn_engine::{RegisterARM64, Unicorn};
use unicorn_engine::unicorn_const::{Arch, Mode, Permission, SECOND_SCALE};
use goblin::elf::program_header::{PF_R, PF_W, PF_X, PT_LOAD};
use goblin::elf::sym::STT_FUNC;
use goblin::elf::{Elf, Sym};
use capstone::arch::arm64::ArchMode;
use capstone::Capstone;
use capstone::arch::BuildsCapstone;

const EMU_BASE_ADDR: u64 = 0x100000;
const EMU_DYN_ADDR: u64 = 0x400000;
const EMU_STACK_ADDR: u64 = 0x800000;
const EMU_STACK_SIZE: u64 = 8 * 1024 * 1024;
const UNICORN_ALIGN_BOUND: u64 = 4 * 1024;

#[derive(Parser, Debug)]
pub struct ElfBasedDemoArguments {
    #[arg(long = "source-file", short = 's')]
    source_file: String,
}

pub fn main(args: ElfBasedDemoArguments) {
    let bin_code = std::fs::read(args.source_file)
        .expect("failed to read source file");

    for i in -10..=10 {
        let result = emulate_quick_fib(&bin_code, i);
        println!("emulate quick_fib({}) => {}", i, result);
    }
}

fn emulate_quick_fib(bin_code: &[u8], x: i32) -> i64 {
    let elf = Elf::parse(&bin_code).expect("failed to parse ELF");
    let mut emu = Unicorn::new(Arch::ARM64, Mode::LITTLE_ENDIAN)
        .expect("failed to initialize Unicorn instance");

    load_elf(&mut emu, &elf, &bin_code);
    init_stack(&mut emu);
    add_instruction_trace_hook(&mut emu);

    let (quick_fib_start_address, quick_fib_end_address) = find_function_address_range(&elf, "quick_fib")
        .expect("failed to find 'quick_fib' symbol");

    let transformed_input_value: u64 = u64::from_le_bytes((x as i64).to_le_bytes());
    emu.reg_write(RegisterARM64::W0, transformed_input_value).expect("failed write W0");

    emu.emu_start(
        quick_fib_start_address,
        (quick_fib_end_address - 4) as u64,
        5 * SECOND_SCALE,
        10000
    ).expect("emulation failed");

    let r_w1 = emu.reg_read(RegisterARM64::X0).unwrap();
    let fib_result = i64::from_le_bytes(r_w1.to_le_bytes());

    fib_result
}

fn add_instruction_trace_hook<T>(emu: &mut Unicorn<T>) {
    let cs = Capstone::new()
        .arm64()
        .mode(ArchMode::Arm)
        .build()
        .expect("failed to initialize Capstone disassembler");


    emu.add_code_hook(0, u64::MAX, move |emu, addr, size| {
        let mem_code = emu.mem_read_as_vec(addr, size as usize).unwrap();

        let disasm = cs.disasm_count(&mem_code, addr, 1).unwrap();
        let disasm = disasm.first().unwrap();

        log::debug!("{}", disasm);
    }).expect("failed to add instruction trace hook");
}

fn find_function_address_range(elf: &Elf, name: &str) -> Option<(u64, u64)> {
    let symbol = find_symbol(elf, name)?;

    if symbol.st_type() != STT_FUNC {
        return None;
    }

    let func_start_address = EMU_BASE_ADDR + symbol.st_value;
    let func_end_address = func_start_address + symbol.st_size;
    let func_range_address = (func_start_address, func_end_address);

    Some(func_range_address)
}

fn find_symbol(elf: &Elf, name: &str) -> Option<Sym> {
    let syms = &elf.syms;
    let strtab = &elf.strtab;
    syms.iter().find(|sym| {
        strtab.get_at(sym.st_name).map(|n| n == name).unwrap_or(false)
    })
}

fn load_elf<T>(emu: &mut Unicorn<T>, elf: &Elf, elf_content: &[u8]) {
    for prog_header in elf.program_headers.iter().filter(|h| h.p_type == PT_LOAD) {
        let mem_permissions = elf_program_header_flags_to_unicorn_memory_permission(prog_header.p_flags);

        let mem_start_address = EMU_BASE_ADDR + prog_header.p_vaddr;
        let mem_aligned_start_address = align(mem_start_address, UNICORN_ALIGN_BOUND);

        let mem_page_size = align(prog_header.p_memsz, UNICORN_ALIGN_BOUND) as usize;

        if mem_aligned_start_address != mem_start_address {
            emu.mem_map(mem_aligned_start_address - UNICORN_ALIGN_BOUND, UNICORN_ALIGN_BOUND as usize, mem_permissions)
                .expect("failed to map mem segment");
        }

        emu.mem_map(mem_aligned_start_address, mem_page_size, mem_permissions)
            .expect("failed to map mem segment");

        let segment_data_range = std::ops::Range {
            start: (prog_header.p_offset) as usize,
            end: (prog_header.p_offset + prog_header.p_filesz) as usize,
        };
        let segment_data = &elf_content[segment_data_range];

        emu.mem_write(mem_start_address, segment_data).expect("failed to write mem segment");
    }

    init_global_offset_table(emu, elf);
    init_dynamic_link_functions(emu, elf);
}

fn init_global_offset_table<T>(emu: &mut Unicorn<T>, elf: &Elf) {
    for reloc in elf.pltrelocs.iter() {
        if let Some(sym) = elf.dynsyms.get(reloc.r_sym) {
            let got_address = EMU_BASE_ADDR + reloc.r_offset;
            let sym_address = EMU_BASE_ADDR + sym.st_value;
            emu.mem_write(got_address, &sym_address.to_le_bytes())
                .expect("failed to initialize .got section");
        }
    }
}

fn init_dynamic_link_functions<T>(emu: &mut Unicorn<T>, elf: &Elf) {
    emu.mem_map(EMU_DYN_ADDR, UNICORN_ALIGN_BOUND as usize, Permission::EXEC)
        .expect("failed to init dynamic link function table");
    
    let ret_instruction = [0xc0, 0x03, 0x5f, 0xd6];
    for reloc in elf.pltrelocs.iter() {
        if let Some(sym) = elf.dynsyms.get(reloc.r_sym) {
            let got_address = EMU_BASE_ADDR + reloc.r_offset;
            let dyn_address = EMU_DYN_ADDR + (reloc.r_sym as u64)*4;

            let sym_name = elf.dynstrtab.get_at(sym.st_name);
            match sym_name {
                Some("pow") => {
                    emu.add_code_hook(dyn_address, dyn_address+1, |emu, _addr, _size| {
                        let r_d0 = emu.reg_read(RegisterARM64::D0).unwrap();
                        let r_d1 = emu.reg_read(RegisterARM64::D1).unwrap();

                        let x = f64::from_bits(r_d0);
                        let y = f64::from_bits(r_d1);
                        let pow_result = x.powf(y).to_bits();

                        emu.reg_write(RegisterARM64::D0, pow_result).expect("failed to write pow result");
                    }).expect("failed to set dynamic call handler");
                },
                _ => continue,
            };

            emu.mem_write(dyn_address, &ret_instruction)
                .expect("failed to write ret instruction placeholder");
            emu.mem_write(got_address, &dyn_address.to_le_bytes())
                .expect("failed to initialize dynamic function");
        }
    }
}

fn init_stack<T>(emu: &mut Unicorn<T>) {
    emu.mem_map(EMU_STACK_ADDR, EMU_STACK_SIZE as usize, Permission::READ | Permission::WRITE)
        .expect("failed to map stack page");
    emu.reg_write(RegisterARM64::SP, EMU_STACK_ADDR + (EMU_STACK_SIZE / 2))
        .expect("failed write SP register");
}

fn elf_program_header_flags_to_unicorn_memory_permission(p_flags: u32) -> Permission {
    let mut permissions = Permission::NONE;

    if (p_flags & PF_R) != 0 {
        permissions.insert(Permission::READ);
    }

    if (p_flags & PF_W) != 0 {
        permissions.insert(Permission::WRITE);
    }

    if (p_flags & PF_X) != 0 {
        permissions.insert(Permission::EXEC);
    }

    permissions
}

fn align(address: u64, bound: u64) -> u64 {
    (address + bound - 1) & !(bound - 1)
}

