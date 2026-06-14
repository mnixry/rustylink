{
  description = "Rustylink clean-room VPN client";

  inputs = {
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

          stableRust = pkgs.rust-bin.stable.latest.default.override {
            extensions = [
              "clippy"
              "rust-src"
              "rustfmt"
            ];
          };
          nightlyRust = pkgs.rust-bin.nightly.latest.default.override {
            extensions = [
              "rust-src"
              "rustfmt"
            ];
          };
          devRust = pkgs.runCommand "rustylink-dev-rust" { } ''
            mkdir -p "$out/bin"
            ln -s ${nightlyRust}/bin/cargo "$out/bin/cargo"
            ln -s ${nightlyRust}/bin/rustfmt "$out/bin/rustfmt"
            ln -s ${stableRust}/bin/cargo-clippy "$out/bin/cargo-clippy"
            ln -s ${stableRust}/bin/clippy-driver "$out/bin/clippy-driver"
            ln -s ${stableRust}/bin/rustc "$out/bin/rustc"
            ln -s ${stableRust}/bin/rustdoc "$out/bin/rustdoc"
          '';

          craneLib = (inputs.crane.mkLib pkgs).overrideToolchain (_: stableRust);
          cargoSrc =
            with lib.fileset;
            toSource {
              root = ./.;
              fileset = unions [
                ./Cargo.lock
                ./Cargo.toml
                ./crates
                ./package-lock.json
                ./package.json
                ./rustfmt.toml
              ];
            };
          nativeBuildInputs =
            with pkgs;
            [
              importNpmLock.npmConfigHook
              nodejs_22
              pkg-config
            ]
            ++ lib.optionals stdenv.isDarwin [ llvmPackages.bintools ];
          buildInputs = lib.optionals pkgs.stdenv.isDarwin [
            pkgs.apple-sdk
            pkgs.libiconv
          ];
          commonArgs = {
            src = cargoSrc;
            strictDeps = true;
            npmDeps = pkgs.importNpmLock { npmRoot = ./.; };
            inherit buildInputs nativeBuildInputs;
          } // lib.optionalAttrs pkgs.stdenv.isDarwin {
            CPATH = "${pkgs.libiconv}/include";
            LIBRARY_PATH = "${pkgs.libiconv}/lib";
          };
          cargoArtifacts = craneLib.buildDepsOnly commonArgs;
        in
        {
          _module.args = { inherit inputs pkgs stableRust nightlyRust; };

          treefmt = {
            projectRootFile = "flake.nix";
            settings.global.excludes = [
              "artifacts/**"
              "node_modules/**"
              "target/**"
            ];
            programs.nixfmt.enable = true;
            programs.rustfmt = {
              enable = true;
              package = nightlyRust;
            };
            programs.taplo.enable = true;
          };

          formatter = config.treefmt.build.wrapper;

          packages.default = craneLib.buildPackage (
            commonArgs
            // {
              inherit cargoArtifacts;
              cargoExtraArgs = "-p rustylink";
            }
          );

          checks = {
            build = config.packages.default;
            clippy = craneLib.cargoClippy (
              commonArgs
              // {
                inherit cargoArtifacts;
                cargoClippyExtraArgs = "--workspace --all-targets";
              }
            );
            test = craneLib.cargoTest (commonArgs // { inherit cargoArtifacts; });
            treefmt = config.treefmt.build.check ./.;
          };

          devShells.default = pkgs.mkShell (
            {
              packages = with pkgs; [
                config.treefmt.build.wrapper
                devRust
                direnv
                nodejs_22
                pkg-config
                taplo
              ] ++ lib.optionals stdenv.isDarwin [
                apple-sdk
                libiconv
                llvmPackages.bintools
              ];

              RUSTC = "${stableRust}/bin/rustc";
              RUSTDOC = "${stableRust}/bin/rustdoc";
              RUSTFMT = "${nightlyRust}/bin/rustfmt";
            } // lib.optionalAttrs pkgs.stdenv.isDarwin {
              CPATH = "${pkgs.libiconv}/include";
              LIBRARY_PATH = "${pkgs.libiconv}/lib";
            }
          );
        };
    };
}
