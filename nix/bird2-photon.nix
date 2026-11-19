{ bird2 }:

let
  supportedVersions = [
    "2.14"
    "2.18"
    "2.19.3"
    "2.20.0"
  ];
in
assert
  builtins.elem bird2.version supportedVersions
  || throw "Photon's BIRD Babel patch has not been validated against BIRD ${bird2.version}";
bird2.overrideAttrs (old: {
  pname = "bird2-photon";
  patches = (old.patches or [ ]) ++ [ ../patches/bird2-babel-hysteresis.patch ];
  meta = old.meta // {
    mainProgram = "bird";
  };
})
