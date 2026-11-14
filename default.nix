(import
  (
    let
      lock = builtins.fromJSON (builtins.readFile ./flake.lock);
      nixpkgs = lock.nodes.nixpkgs.locked;
    in
    fetchTarball {
      url = "https://github.com/NixOS/nixpkgs/archive/${nixpkgs.rev}.tar.gz";
      sha256 = nixpkgs.narHash;
    }
  )
  { }
).callPackage
  (
    { buildGoModule, lib }:
    let
      version = lib.removeSuffix "\n" (builtins.readFile ./VERSION);
      cleanSrc = lib.cleanSourceWith {
        src = ./.;
        filter = path: type:
          type != "socket"
          && !(lib.hasInfix "/.photon" path)
          && !(lib.hasInfix "/.public-test" path)
          && !(lib.hasInfix "/build" path)
          && !(lib.hasInfix "/dist" path)
          && !(lib.hasSuffix "/result" path);
      };
    in
    buildGoModule {
      pname = "photon";
      inherit version;
      src = cleanSrc;
      vendorHash = "sha256-ZR8wBHmOH/or25G7Py1I/zxonMTtF2Gc/jAowlSsoQw=";
      subPackages = [ "app/photon" "app/photon-services" ];
      doCheck = false;
      ldflags = [
        "-s"
        "-w"
        "-X main.buildCommit=unknown"
        "-X main.buildDescribe=v${version}"
        "-X main.buildDirty=true"
        "-X main.buildTime=unknown"
      ];
      meta = {
        description = "Trust-first network configuration control plane";
        homepage = "https://github.com/HiggsNet/photon";
        license = lib.licenses.mit;
        mainProgram = "photon";
        platforms = lib.platforms.linux;
      };
    }
  )
  { }
