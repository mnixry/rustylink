{
  inputs,
  buf,
  pnpm_10,
  nodejs,
  mkPnpmPackage,
}:
let
  pnpm = pnpm_10;
  inherit (inputs) self;
in
mkPnpmPackage {
  src = ./.;
  inherit nodejs pnpm;
  extraBuildInputs = [ buf ];
  prePatch = ''
    substituteInPlace buf.gen.yaml \
      --replace-fail 'directory: ../crates/proto/proto' 'directory: ${self}/crates/proto/proto'
  '';
  installInPlace = true;
}
