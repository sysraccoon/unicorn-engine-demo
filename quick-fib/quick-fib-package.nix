{
  stdenv,
  cmake,
}:
stdenv.mkDerivation {
  name = "quick-fib-demo";
  src = ./.;

  nativeBuildInputs = [
    cmake
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
    cp quick-fib-demo $out/bin

    mkdir -p $out/lib
    cp *.so $out/lib
    # mkdir -p $out/lib
    # cp libquick-fib.so $out/lib/libquick-fib.so
    #
    # mkdir -p $out/bin
    # cp quick-fib-demo $out/bin/quick-fib
  '';
}
