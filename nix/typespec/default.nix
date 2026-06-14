{
  lib,
  mkPnpmPackage,
  nodejs,
  pnpm_10,
  runCommand,
  makeWrapper,
}:
let
  builtPackage = mkPnpmPackage {
    src = ./.;
    pnpm = pnpm_10;
    inherit nodejs;
  };
  inherit (builtPackage.passthru) nodeModules;
in
runCommand builtPackage.name { buildInputs = [ makeWrapper ]; } ''
  mkdir -p $out/bin
  for bin in ${nodeModules}/node_modules/.bin/*; do
    makeWrapper $bin $out/bin/$(basename $bin) \
      --prefix PATH : ${lib.makeBinPath [ nodejs ]}
  done
''
