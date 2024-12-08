{
  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-24.11";
    flake-utils.url = "github:numtide/flake-utils";
  };
  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs-aarch64 = import nixpkgs {
          inherit system;
          crossSystem = {
            config = "aarch64-unknown-linux-musl";
          };
        };

        quick-fib-package = pkgs-aarch64.callPackage ./quick-fib-package.nix {};
      in
      {
        packages = rec {
          quick-fib-demo = quick-fib-package;
          default = quick-fib-demo;
        };
        apps = rec {
          quick-fib-demo = flake-utils.lib.mkApp {
            drv = self.packages.${system}.quick-fib-demo;
            exePath = "/bin/quick-fib-demo";
          };
          default = quick-fib-demo;
        };
    });
}
