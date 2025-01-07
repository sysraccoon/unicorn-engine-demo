# Unicorn Engine Demo

Original Video: [link](https://example.com) (TODO add actual link to video)

## Project Setup

Projects can be built by using [nix](https://nixos.org/guides/how-nix-works/):

```bash
cd unicorn-doc-demo # unicorn-rs-demo | quick-fib
nix build
./result/bin/unicorn-doc-demo
# shortcut variant
nix run
```

You can get related dependencies by using [nix develop](https://nix.dev/manual/nix/2.17/command-ref/new-cli/nix3-develop) or [nix-direnv](https://github.com/nix-community/nix-direnv) command:
```bash
cd unicorn-doc-demo
nix develop
# or
direnv allow
```

C projects (unicorn-doc-demo and quick-fib) can be built by using make:
```bash
cd unicorn-doc-demo
make
./unicorn-doc-demo
```

Rust project (unicorn-rs-demo) can be built by using cargo:
```bash
cd unicorn-rs-demo
cargo build
./target/debug/unicorn-rs-demo
# shortcut variant
cargo run
```

Rust project allow to select demo variant by using parameter and pass shared object
```bash
cd unicorn-rs-demo
cargo run -- simple --source-file samples/libquick-fib.static.so
```

You also can enable emulation instruction trace by using `RUST_LOG`:
```bash
cd unicorn-rs-demo
RUST_LOG=debug cargo run -- simple --source-file samples/libquick-fib.static.so
```
