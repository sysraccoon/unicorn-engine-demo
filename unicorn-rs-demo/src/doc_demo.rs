use unicorn_engine::{Arch, Mode, Permission, RegisterX86, Unicorn};

const X86_CODE32: [u8; 2] = [0x41, 0x4a]; // INC ecx; DEC edx

const ADDRESS: u64 = 0x1000000;

pub fn main() {
    println!("Emulate i386 code");

    let mut emu = Unicorn::new(Arch::X86, Mode::MODE_32)
        .expect("failed to initialize Unicorn instance");

    emu.mem_map(ADDRESS, 2 * 1024 * 1024, Permission::ALL)
        .expect("failed to map memory");

    emu.mem_write(ADDRESS, &X86_CODE32)
        .expect("failed to write emulation code to memory");

    let r_ecx = 0x1234;
    let r_edx = 0x7890;

    emu.reg_write(RegisterX86::ECX, r_ecx)
        .expect("failed to write to ECX register");
    emu.reg_write(RegisterX86::EDX, r_edx)
        .expect("failed to write to EDX register");

    emu.emu_start(ADDRESS, ADDRESS + (X86_CODE32.len() as u64), 0, 0)
        .expect("failed to emulate x86 code");

    println!(">>> ECX = 0x{:02x}", emu.reg_read(RegisterX86::ECX).unwrap());
    println!(">>> EDX = 0x{:02x}", emu.reg_read(RegisterX86::EDX).unwrap());
}
