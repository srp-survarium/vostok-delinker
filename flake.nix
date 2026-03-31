{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    rust-overlay.url = "github:oxalica/rust-overlay";
  };

  outputs =
    {
      self,
      nixpkgs,
      rust-overlay,
    }:
    let
      system = "x86_64-linux";
      pkgs = import nixpkgs {
        inherit system;
        overlays = [ rust-overlay.overlays.default ];
      };
    in
    {
      devShells.${system}.default = pkgs.mkShell {
        nativeBuildInputs = with pkgs; [
          (rust-bin.nightly.latest.default.override {
            extensions = [
              "rust-analyzer"
              "rust-src"
            ];
          })
          rustfmt
          git
          pkg-config
          openssl
        ];
        hellHook = ''
          unset NIX_CFLAGS_COMPILE
        '';
      };
    };
}
