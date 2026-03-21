{
  description = "tapkey - derive keys from passkeys";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
        isDarwin = pkgs.stdenv.isDarwin;

        # Pre-built release binaries (built in CI with attestation)
        # Updated automatically by the release workflow
        releases = {
          aarch64-darwin = {
            url = "https://github.com/jul-sh/tapkey/releases/download/v2.1.0/tapkey-v2.1.0-arm64.zip";
            hash = "sha256-9J4FQfdeQ2p9ERXsC7sTtTLu9mTdhM6/XXULh0OKqtY=";
          };
          x86_64-linux = {
            url = "https://github.com/jul-sh/tapkey/releases/download/v2.1.0/tapkey-v2.1.0-linux-x86_64.zip";
            hash = "sha256-VXEBShupgX7UNcFRBRkcQ3e/tgbDTcXE6ukLddp8x+E=";
          };
        };
      in
      {
        packages = pkgs.lib.optionalAttrs (builtins.hasAttr system releases) {
          default = pkgs.stdenv.mkDerivation {
            pname = "tapkey";
            version = "2.2.0";
            src = pkgs.fetchurl {
              inherit (releases.${system}) url hash;
            };
            sourceRoot = ".";
            nativeBuildInputs = [ pkgs.unzip ];
            unpackPhase = "unzip $src";
            installPhase = if isDarwin then ''
              mkdir -p $out/share/tapkey $out/bin
              cp -R Tapkey.app $out/share/tapkey/
              ln -s $out/share/tapkey/Tapkey.app/Contents/MacOS/tapkey $out/bin/tapkey
            '' else ''
              mkdir -p $out/bin
              cp tapkey $out/bin/tapkey
              chmod +x $out/bin/tapkey
            '';
          };
        };

        devShells.default = pkgs.mkShell {
          buildInputs = with pkgs; [
            age
            gh
            rustc
            cargo
            rustfmt
            clippy
            nodePackages.wrangler
          ];

          shellHook = if isDarwin then ''
            export PATH="/usr/bin:$PATH"
            unset SDKROOT DEVELOPER_DIR
          '' else "";
        };
      });
}
