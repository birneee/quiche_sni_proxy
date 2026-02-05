{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-parts.url = "github:hercules-ci/flake-parts";
    rust-overlay.url = "github:oxalica/rust-overlay";
  };
  outputs =
    inputs@{
      nixpkgs,
      flake-parts,
      rust-overlay,
      ...
    }:
    flake-parts.lib.mkFlake { inherit inputs; } {
      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "aarch64-darwin"
        "x86_64-darwin"
      ];
      perSystem =
        {
          self',
          system,
          ...
        }:
        let
          pkgs = import nixpkgs {
            inherit system;
            overlays = [ (import rust-overlay) ];
          };
          manifest = (pkgs.lib.importTOML ./Cargo.toml).package;
          rustToolchain = pkgs.rust-bin.stable."1.92.0".default.override {
            extensions = [
              "rust-src"
              "clippy"
              "rustfmt"
              "rust-analyzer"
            ];
          };
          rustPlatform = pkgs.makeRustPlatform {
            cargo = rustToolchain;
            rustc = rustToolchain;
          };
        in
        {
          packages.default = rustPlatform.buildRustPackage {
            pname = manifest.name;
            version = manifest.version;
            cargoLock = {
              lockFile = ./Cargo.lock;
              outputHashes = {
                "octets-0.3.4" = "sha256-0ii+zxtXbMokQgsBKydz/Pa+Exuxrx48MRjY1+NR11Q=";
                "quiche_endpoint-0.1.0" = "sha256-j+/0UKKS2uQ4guGx3JFqy0vxgISLY5fGtlF8w7Xj5/I=";
                "quiche_mio_runner-0.1.0" = "sha256-a3wIvAmonFX8l35uu6p8veCxz5wzh0WbU6zKt7PntCU=";
              };
            };
            src = pkgs.lib.cleanSource ./.;
            nativeBuildInputs = with pkgs; [
              clang
              cmake
              git
            ];
            env = {
              LIBCLANG_PATH = "${pkgs.llvmPackages.libclang.lib}/lib";
            };
          };
          devShells.default = pkgs.mkShell {
            inputsFrom = [ self'.packages.default ];
            LIBCLANG_PATH = "${pkgs.llvmPackages.libclang.lib}/lib";
            RUST_SRC_PATH = "${rustToolchain}/lib/rustlib/src/rust/library";
            shellHook = ''
              # Symlink for IDEs
              ln -sfn ${rustToolchain} $PWD/.rust-toolchain
            '';
          };
        };
    };
}
