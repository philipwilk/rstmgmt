{
  description = "rust nightly with openssl";
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    rust-overlay.url = "github:oxalica/rust-overlay";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = {
    self,
    nixpkgs,
    rust-overlay,
    flake-utils,
    ...
  }:
    flake-utils.lib.eachDefaultSystem (
      system: let
        overlays = [(import rust-overlay)];
        pkgs = import nixpkgs {
          inherit system overlays;
        };
      in {
        devShells.default = pkgs.mkShell {
          buildInputs = with pkgs; [
            openssl
            pkg-config
            exa
            fd
            (rust-bin.selectLatestNightlyWith (toolchain:
              toolchain.default.override {
                extensions = ["rust-src"];
              }))
          ];

          shellHook = ''
            alias ls=exa
            alias find=fd
            cargo install sea-orm-cli
            alias sea-orm-cli=$HOME/.cargo/bin/sea-orm-cli
          '';
        };
      }
    );
}
