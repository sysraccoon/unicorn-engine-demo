{
  stdenv,
  unicorn,
}:
stdenv.mkDerivation {
  name = "unicorn-doc-demo";
  src = ./.;

  propagatedBuildInputs = [
    unicorn
  ];

  installFlags = [
    "DESTDIR=$(out)"
    "PREFIX="
  ];
}
