{
  stdenv,
}:
stdenv.mkDerivation {
  name = "quick-fib-demo";
  src = ./.;

  installFlags = [
    "DESTDIR=$(out)"
    "PREFIX="
  ];
}
