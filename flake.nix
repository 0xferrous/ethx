{
  description = "ethx";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    crane.url = "github:ipetkov/crane";
  };

  outputs = { self, nixpkgs, flake-utils, crane }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs {
          inherit system;
        };

        craneLib = crane.mkLib pkgs;
        src = craneLib.cleanCargoSource ./.;

        commonArgs = {
          inherit src;
          strictDeps = true;

          cargoLock = ./Cargo.lock;

          outputHashes = {
            "git+https://github.com/alloy-rs/alloy?rev=100a3325ac4d624f3eb0bd404125750e76edf8ca#100a3325ac4d624f3eb0bd404125750e76edf8ca" = "sha256-bN7DxLEAgXsxdcZN+U4O0bKTz3SKqlfwnrNH+wuais0=";
          };

          nativeBuildInputs = [
            pkgs.pkg-config
          ];

        };

        cargoArtifacts = craneLib.buildDepsOnly commonArgs;

        ethx = craneLib.buildPackage (commonArgs
          // {
            inherit cargoArtifacts;
            cargoExtraArgs = "--package ethx";
            doCheck = false;
          });
      in
      {
        packages = {
          default = ethx;
          ethx = ethx;
        };

        apps = {
          default = flake-utils.lib.mkApp {
            drv = ethx;
          };
          ethx = flake-utils.lib.mkApp {
            drv = ethx;
          };
        };
      });
}
