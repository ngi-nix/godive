{
  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    gomod2nix.url = "github:tweag/gomod2nix";
  };

  outputs =
    { self
    , nixpkgs
    , flake-utils
    , gomod2nix
    }:
      let
        overlays = [ gomod2nix.overlay ];
      in
        flake-utils.lib.eachDefaultSystem (
          system:
            let
              pkgs = import nixpkgs { inherit system overlays; };
            in
              rec {
                defaultPackage = pkgs.buildGoApplication {
                  pname = "godive";
                  version = "0.1";
                  src = ./.;
                  modules = ./gomod2nix.toml;
                };

                devShell = pkgs.mkShell {
                  buildInputs = [ pkgs.go ];
                };
              }
        );
}
