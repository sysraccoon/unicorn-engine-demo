{
  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-24.11";
    flake-utils.url = "github:numtide/flake-utils";
  };
  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs {
          inherit system;
        };

        unicorn-rs-demo-package = pkgs.callPackage ./unicorn-rs-demo-package.nix {};
      in
      {
        packages = rec {
          unicorn-engine-demo = unicorn-rs-demo-package;
          default = unicorn-engine-demo;
        };
        apps = rec {
          unicorn-engine-demo = flake-utils.lib.mkApp {
            drv = self.packages.${system}.unicorn-engine-demo;
          };
          default = unicorn-engine-demo;
        };
        devShells.default = pkgs.mkShell {
          buildInputs =
            unicorn-rs-demo-package.nativeBuildInputs
            ++ (with pkgs; [
              cargo
            ]);
        };
    });
}
