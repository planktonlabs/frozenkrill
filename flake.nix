{
  description = "Rust project with musl target on x86_64, host toolchain elsewhere";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs { inherit system; };
        isX86_64Linux = system == "x86_64-linux";
        muslCC = pkgs.pkgsStatic.stdenv.cc;
      in
      {
        devShells.default = pkgs.mkShell ({
          packages = with pkgs; [
            bashInteractive
            rustc
            cargo
            rustfmt
            clippy
            rust-analyzer
            pkg-config
            cargo-edit
          ] ++ pkgs.lib.optionals isX86_64Linux [ muslCC ];

          RUST_SRC_PATH = "${pkgs.rustPlatform.rustLibSrc}";

          shellHook = pkgs.lib.optionalString (!isX86_64Linux) ''
            export CARGO_BUILD_TARGET="$(rustc -vV | sed -n 's/^host: //p')"
          '';
        } // pkgs.lib.optionalAttrs isX86_64Linux {
          CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER = "${muslCC}/bin/${muslCC.targetPrefix}cc";
          CC_x86_64_unknown_linux_musl = "${muslCC}/bin/${muslCC.targetPrefix}cc";
        });
      }
    );
}
