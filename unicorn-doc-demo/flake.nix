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

        unicorn-doc-demo-package = pkgs.callPackage ./unicorn-doc-demo-package.nix {};
      in
      {
        packages = rec {
          unicorn-doc-demo = unicorn-doc-demo-package;
          default = unicorn-doc-demo;
        };
        apps = rec {
          unicorn-doc-demo = flake-utils.lib.mkApp {
            drv = self.packages.${system}.unicorn-doc-demo;
          };
          default = unicorn-doc-demo;
        };
        devShells.default = pkgs.mkShell {
          buildInputs =
            unicorn-doc-demo-package.nativeBuildInputs
            ++ (with pkgs; [

          ]);
        };
    });
}
