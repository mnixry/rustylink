{
  # spell-checker: disable
  inputs = {
    self.submodules = true;
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    flake-parts = {
      url = "github:hercules-ci/flake-parts";
      inputs.nixpkgs-lib.follows = "nixpkgs";
    };
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    treefmt-nix = {
      url = "github:numtide/treefmt-nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    crane.url = "github:ipetkov/crane";
  };

  outputs =
    { flake-parts, ... }@inputs:
    flake-parts.lib.mkFlake { inherit inputs; } {
      systems = inputs.nixpkgs.lib.systems.flakeExposed;
      imports = [ inputs.treefmt-nix.flakeModule ];
      perSystem =
        {
          config,
          lib,
          system,
          ...
        }:
        let
          pkgs = import inputs.nixpkgs {
            inherit system;
            overlays = [ (import inputs.rust-overlay) ];
          };
          rust = pkgs.rust-bin.stable.latest.default.override {
            extensions = [
              "rust-src"
              "llvm-tools-preview"
            ];
          };
          rustfmt = pkgs.rust-bin.selectLatestNightlyWith (toolchain: toolchain.rustfmt);
          craneLib = (inputs.crane.mkLib pkgs).overrideToolchain (_: rust);
          craneCommonArgs = rec {
            src = ./.;
            inherit (craneLib.crateNameFromCargoToml { inherit src; }) version;
            nativeBuildInputs = [ ];
            strictDeps = true;
            cargoVendorDir = craneLib.vendorMultipleCargoDeps {
              inherit (craneLib.findCargoFiles src) cargoConfigs;
              cargoLockList = [
                ./Cargo.lock
                "${rust}/lib/rustlib/src/rust/library/Cargo.lock"
              ];
            };
          };
          cargoArtifacts = craneLib.buildDepsOnly craneCommonArgs;
        in
        {
          _module.args = { inherit inputs pkgs rust; };
          treefmt =
            { ... }:
            {
              projectRootFile = ".git/config";
              programs.buf.enable = true;
              programs.nixfmt.enable = true;
              programs.taplo.enable = true;
              programs.rustfmt = {
                enable = true;
                package = rustfmt;
              };
              programs.yamlfmt.enable = true;
            };
          devShells.default = pkgs.mkShell {
            inherit (pkgs) stdenv;
            inputsFrom = [ config.treefmt.build.devShell ];
            buildInputs = [
              (lib.hiPrio rustfmt)
              rust
            ]
            ++ (
              with pkgs;
              [
                cargo-edit
                cargo-nextest

                buf
                protobuf
              ]
              ++ lib.optionals stdenv.isLinux [
                llvmPackages.bolt
                perf
              ]
              ++ lib.optionals stdenv.isDarwin [
                darwin.libiconv
                darwin.libresolv
              ]
            );
            env = lib.optionalAttrs pkgs.stdenv.isDarwin { SDKROOT = pkgs.apple-sdk.sdkroot; };
          };
          checks = {
            clippy = craneLib.cargoClippy (
              craneCommonArgs
              // {
                inherit cargoArtifacts;
                cargoClippyExtraArgs = "--all-targets --all-features";
              }
            );
            test = craneLib.cargoNextest (
              craneCommonArgs
              // {
                inherit cargoArtifacts;
              }
            );
          };

          packages.default = craneLib.buildPackage (
            craneCommonArgs
            // {
              inherit cargoArtifacts;
              doCheck = false;
            }
          );
        };
    };
}
