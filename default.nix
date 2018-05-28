with import <nixpkgs> {};

stdenv.mkDerivation {
  name = "my-env";
  src = ./src;

  buildInputs = [
    rustup
  ];
}
