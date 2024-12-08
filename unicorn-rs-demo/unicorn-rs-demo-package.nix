{
  rustPlatform,
  unicorn,
  cmake,
  pkg-config,
  capstone,
}:

rustPlatform.buildRustPackage rec {
  name = "unicorn-rs-demo-package";
  src = ./.;

  cargoLock = {
    lockFile = ./Cargo.lock;
    allowBuiltinFetchGit = true;
  };

  nativeBuildInputs = [
    pkg-config
    cmake
    unicorn
    capstone
  ];
}

