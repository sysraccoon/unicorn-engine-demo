{
  stdenv,
  cmake,
  unicorn,
}:
stdenv.mkDerivation {
  name = "unicorn-doc-demo";
  src = ./.;

  nativeBuildInputs = [
    cmake
  ];

  propagatedBuildInputs = [
    unicorn
  ];

  configurePhase = ''
    mkdir -p build
    cd build
    cmake ../src
  '';

  buildPhase = ''
    make
  '';

  installPhase = ''
    mkdir -p $out/bin
    cp unicorn-doc-demo $out/bin/unicorn-doc-demo
  '';
}
