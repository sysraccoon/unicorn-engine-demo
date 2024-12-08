mod doc_demo;
mod simple_demo;
mod elf_based_demo;

use clap::Parser;
use elf_based_demo::ElfBasedDemoArguments;
use simple_demo::SimpleDemoArguments;

#[derive(Parser, Debug)]
#[clap(author = "sysraccoon", version, about)]
struct AppArguments {
    #[clap(subcommand)]
    subcommand: AppSubCommand,
}

#[derive(Parser, Debug)]
enum AppSubCommand {
    Doc,
    Simple(SimpleDemoArguments),
    ElfBased(ElfBasedDemoArguments),
}

fn main() {
    env_logger::init();

    let args = AppArguments::parse();

    match args.subcommand {
        AppSubCommand::Doc => doc_demo::main(),
        AppSubCommand::Simple(subcommand_args) => simple_demo::main(subcommand_args),
        AppSubCommand::ElfBased(subcommand_args) => elf_based_demo::main(subcommand_args),
    };
}
