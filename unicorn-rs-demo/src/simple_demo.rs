use clap::Parser;
use unicorn_engine::{RegisterARM64, Unicorn};
use unicorn_engine::unicorn_const::{Arch, Mode, Permission, SECOND_SCALE};
use capstone::arch::arm64::ArchMode;
use capstone::Capstone;
use capstone::arch::BuildsCapstone;

#[derive(Parser, Debug)]
pub struct SimpleDemoArguments {
    #[arg(long = "source-file", short = 's')]
    source_file: String,
}

pub fn main(args: SimpleDemoArguments) {
    let bin_code = std::fs::read(args.source_file)
        .expect("failed to read source file");

    for i in -10..=10 {
        let result = emulate_quick_fib(&bin_code, i);
        println!("emulate quick_fib({}) => {}", i, result);
    }
}

fn emulate_quick_fib(bin_code: &[u8], x: i32) -> i64 {
    let mut unicorn = Unicorn::new(Arch::ARM64, Mode::LITTLE_ENDIAN).expect("failed to initialize Unicorn instance");
    let emu = &mut unicorn;

    let code_base_addr = 0x100000;
    let code_size: u64 = 1024*1024*8;

    let quick_fib_start_address = 0x1006a0;
    let quick_fib_end_address = 0x100720;

    emu.mem_map(code_base_addr, code_size as usize, Permission::ALL).expect("failed to map code page");
    emu.mem_write(code_base_addr, &bin_code).expect("failed to write instructions");

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
    }).expect("fail to add code hook");

    let bl_pow_addresses = [
        0x1006cc,
        0x1006fc,
    ];
    for bl_pow_addr in bl_pow_addresses {
        let nop_instruction = [0x1f, 0x20, 0x03, 0xd5];
        emu.mem_write(bl_pow_addr, &nop_instruction).expect("failed to write nop instruction");
        emu.add_code_hook(bl_pow_addr, bl_pow_addr+1, |emu, _addr, _size| {
            let r_d0 = emu.reg_read(RegisterARM64::D0).unwrap();
            let r_d1 = emu.reg_read(RegisterARM64::D1).unwrap();

            let x = f64::from_bits(r_d0);
            let y = f64::from_bits(r_d1);
            let pow_result = x.powf(y).to_bits();

            emu.reg_write(RegisterARM64::D0, pow_result).expect("failed to write pow result");
        }).expect("fail to add jmp hook");
    }

    let stack_base_addr = 0x8000000;
    let stack_size: u64 = 1024*1024*40;
    emu.mem_map(stack_base_addr, stack_size as usize, Permission::ALL).expect("failed to map stack page");
    emu.reg_write(RegisterARM64::SP, stack_base_addr + (stack_size / 2)).expect("failed write SP register");

    let transformed_input_value: u64 = u64::from_le_bytes((x as i64).to_le_bytes());
    emu.reg_write(RegisterARM64::W0, transformed_input_value).expect("failed write W0");

    emu.emu_start(quick_fib_start_address, (quick_fib_end_address) as u64, 10 * SECOND_SCALE, 100000).expect("emulation failed");

    let r_w1 = emu.reg_read(RegisterARM64::X0).unwrap();
    let fib_result = i64::from_le_bytes(r_w1.to_le_bytes());

    fib_result
}

