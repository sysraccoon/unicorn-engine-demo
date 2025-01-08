use clap::Parser;
use unicorn_engine::{RegisterARM64, Unicorn};
use unicorn_engine::unicorn_const::{Arch, Mode, Permission, SECOND_SCALE};
use goblin::elf::program_header::{PF_R, PF_W, PF_X, PT_LOAD};
use goblin::elf::sym::STT_FUNC;
use goblin::elf::Elf;
use capstone::arch::arm64::ArchMode;
use capstone::Capstone;
use capstone::arch::BuildsCapstone;

const EMU_BASE_ADDR: u64 = 0x100000;
const EMU_STACK_ADDR: u64 = 0x800000;
const EMU_STACK_SIZE: u64 = 8 * 1024 * 1024;
const UNICORN_ALIGN_BOUND: u64 = 4 * 1024;
const EMU_DYN_ADDR: u64 = EMU_BASE_ADDR - UNICORN_ALIGN_BOUND;
const ARM64_INSTR_SIZE: u64 = 4;

#[derive(Parser, Debug)]
pub struct ElfBasedDemoArguments {
    #[arg(long = "source-file", short = 's')]
    source_file: String,
}

pub fn main(args: ElfBasedDemoArguments) {
    let bin_code = std::fs::read(args.source_file)
        .expect("failed to read source file");

    for i in -50..=50 {
        let result = emulate_quick_fib(&bin_code, i);
        println!("emulate quick_fib({}) => {}", i, result);
    }
}

fn emulate_quick_fib(bin_code: &[u8], source_value: i32) -> i64 {
    let elf = Elf::parse(&bin_code).expect("failed to parse ELF");
    let mut emu = Unicorn::new(Arch::ARM64, Mode::LITTLE_ENDIAN)
        .expect("failed to initialize Unicorn instance");

    load_elf(&mut emu, &elf, &bin_code);
    add_instruction_trace_hook(&mut emu);

    let (quick_fib_start, quick_fib_end) = find_function_address_range(&elf, "quick_fib")
        .expect("failed to find 'quick_fib' symbol");

    let source_value: u64 = source_value as u64;
    emu.reg_write(RegisterARM64::W0, source_value)
        .expect("failed write W0");

    emu.emu_start(quick_fib_start, quick_fib_end, 5 * SECOND_SCALE, 10000)
        .expect("emulation failed");

    let r_x0 = emu.reg_read(RegisterARM64::X0).unwrap();
    let fib_result = r_x0 as i64;

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
    let symbol = elf.syms.iter().find(|sym| {
        elf.strtab.get_at(sym.st_name).map(|n| n == name).unwrap_or(false)
    })?;

    if symbol.st_type() != STT_FUNC {
        return None;
    }

    let func_start_address = EMU_BASE_ADDR + symbol.st_value;
    let func_end_address = func_start_address + symbol.st_size - ARM64_INSTR_SIZE;
    let func_range_address = (func_start_address, func_end_address);

    Some(func_range_address)
}

fn load_elf<T>(emu: &mut Unicorn<T>, elf: &Elf, elf_content: &[u8]) {
    init_segments(emu, elf, elf_content);
    init_global_offset_table(emu, elf);
    init_dynamic_link_functions(emu, elf);
    init_stack(emu);
}

fn init_segments<T>(emu: &mut Unicorn<T>, elf: &Elf, elf_content: &[u8]) {
    for prog_header in elf.program_headers.iter().filter(|h| h.p_type == PT_LOAD) {
        let mem_start_address = EMU_BASE_ADDR + prog_header.p_vaddr;
        let mem_end_address = mem_start_address + prog_header.p_memsz;

        let align_bound = UNICORN_ALIGN_BOUND;
        let mem_aligned_start_address = align_down(mem_start_address, align_bound);
        let mem_aligned_end_address = align_up(mem_end_address, align_bound);

        let mem_page_size = (mem_aligned_end_address - mem_aligned_start_address) as usize;

        let mem_permissions = program_flags_to_mem_permission(prog_header.p_flags);

        emu.mem_map(mem_aligned_start_address, mem_page_size, mem_permissions)
            .expect("failed to map mem segment");

        let segment_data_range = std::ops::Range {
            start: (prog_header.p_offset) as usize,
            end: (prog_header.p_offset + prog_header.p_filesz) as usize,
        };
        let segment_data = &elf_content[segment_data_range];

        emu.mem_write(mem_start_address, segment_data)
            .expect("failed to write mem segment");
    }
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
    
    let mut dyn_offset = 0;
    let ret_instruction = [0xc0, 0x03, 0x5f, 0xd6];
    for reloc in elf.pltrelocs.iter() {
        if let Some(sym) = elf.dynsyms.get(reloc.r_sym) {
            let got_address = EMU_BASE_ADDR + reloc.r_offset;
            let dyn_address = EMU_DYN_ADDR + dyn_offset;

            let sym_name = elf.dynstrtab.get_at(sym.st_name);
            match sym_name {
                Some("pow") => {
                    emu.add_code_hook(dyn_address, dyn_address+1, |emu, _addr, _size| {
                        let r_d0 = emu.reg_read(RegisterARM64::D0).unwrap();
                        let r_d1 = emu.reg_read(RegisterARM64::D1).unwrap();

                        let x = f64::from_bits(r_d0);
                        let y = f64::from_bits(r_d1);
                        let pow_result = x.powf(y).to_bits();

                        emu.reg_write(RegisterARM64::D0, pow_result)
                            .expect("failed to write pow result");
                    }).expect("failed to set dynamic call handler");
                },
                _ => continue,
            };

            emu.mem_write(dyn_address, &ret_instruction)
                .expect("failed to write ret instruction placeholder");
            emu.mem_write(got_address, &dyn_address.to_le_bytes())
                .expect("failed to initialize dynamic function");

            dyn_offset += ret_instruction.len() as u64;
        }
    }
}

fn init_stack<T>(emu: &mut Unicorn<T>) {
    emu.mem_map(EMU_STACK_ADDR, EMU_STACK_SIZE as usize, Permission::READ | Permission::WRITE)
        .expect("failed to map stack page");
    emu.reg_write(RegisterARM64::SP, EMU_STACK_ADDR + (EMU_STACK_SIZE / 2))
        .expect("failed write SP register");
}

fn program_flags_to_mem_permission(p_flags: u32) -> Permission {
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

fn align_up(address: u64, bound: u64) -> u64 {
    assert!(bound.is_power_of_two());
    (address + bound - 1) & !(bound - 1)
}

fn align_down(address: u64, bound: u64) -> u64 {
    assert!(bound.is_power_of_two());
    address & !(bound - 1)
}
