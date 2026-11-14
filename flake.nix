{
  description = "Photon trust-first network configuration system";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  };

  outputs =
    { self, nixpkgs }:
    let
      supportedSystems = [
        "x86_64-linux"
        "aarch64-linux"
      ];
      forAllSystems = nixpkgs.lib.genAttrs supportedSystems;
    in
    {
      packages = forAllSystems (
        system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
          version = pkgs.lib.removeSuffix "\n" (builtins.readFile ./VERSION);
          cleanSrc = pkgs.lib.cleanSourceWith {
            src = ./.;
            filter =
              path: type:
              type != "socket"
              && !(pkgs.lib.hasInfix "/.photon" path)
              && !(pkgs.lib.hasInfix "/.public-test" path)
              && !(pkgs.lib.hasInfix "/build" path)
              && !(pkgs.lib.hasInfix "/dist" path)
              && !(pkgs.lib.hasSuffix "/result" path);
          };
          photon = pkgs.buildGoModule {
            pname = "photon";
            inherit version;
            src = cleanSrc;
            vendorHash = "sha256-ZR8wBHmOH/or25G7Py1I/zxonMTtF2Gc/jAowlSsoQw=";

            subPackages = [
              "app/photon"
              "app/photon-services"
            ];
            # Unit and root smoke tests are run explicitly by CI/Make targets.
            # Nix packaging only needs to compile the installable binaries.
            doCheck = false;

            ldflags = [
              "-X main.buildCommit=${self.shortRev or "unknown"}"
              "-X main.buildDescribe=v${version}"
              "-X main.buildDirty=${if self ? rev then "false" else "true"}"
              "-X main.buildTime=unknown"
            ];

            meta = {
              description = "Trust-first network configuration control plane";
              homepage = "https://github.com/HiggsNet/photon";
              license = pkgs.lib.licenses.mit;
              mainProgram = "photon";
              platforms = pkgs.lib.platforms.linux;
            };
          };
        in
        {
          default = photon;
          photon = photon;
        }
      );

      nixosModules.default =
        {
          config,
          lib,
          pkgs,
          ...
        }:
        let
          cfg = config.services.photon;
          settingsFormat = pkgs.formats.yaml { };
          generatedConfig = settingsFormat.generate "photon-config.yaml" cfg.settings;
          configFile =
            if cfg.configFile != null then
              cfg.configFile
            else
              "/etc/photon/config.yaml";
          generatedConfigRestartTriggers =
            lib.optional (cfg.configFile == null && cfg.settings != { }) generatedConfig;
          settingsIPsecConfigured = cfg.settings ? ipsec;
          settingsIPsec = cfg.settings.ipsec or { };
          settingsIPsecDriver = settingsIPsec.driver or "strongswan";
          settingsIPsecPortMode = settingsIPsec.port_mode or "fixed";
          settingsIPsecPortRange = settingsIPsec.port_range or null;
          validPortRange =
            range:
            range != null
            && builtins.isAttrs range
            && range ? from
            && range ? to
            && builtins.isInt range.from
            && builtins.isInt range.to
            && range.from >= 0
            && range.from <= 65535
            && range.to >= 0
            && range.to <= 65535
            && range.from <= range.to;
          inferIPsecFirewall = settingsIPsecConfigured && settingsIPsecDriver != "dry-run";
          openIPsecFirewall = cfg.openFirewall && (inferIPsecFirewall || cfg.ipsecFirewall.enable);
          inferredIPsecPortRange = if settingsIPsecPortMode == "range" then settingsIPsecPortRange else null;
          effectiveIPsecPortRange =
            if cfg.ipsecFirewall.portRange != null then cfg.ipsecFirewall.portRange else inferredIPsecPortRange;
          deploymentCfg = cfg.serviceDeployment;
          generatedServiceManifest = settingsFormat.generate "photon-service.yaml" deploymentCfg.settings;
          serviceManifestFile =
            if deploymentCfg.configFile != null then
              deploymentCfg.configFile
            else
              "/etc/photon/service.yaml";
          generatedServiceManifestRestartTriggers =
            lib.optional (deploymentCfg.configFile == null && deploymentCfg.settings != { })
              generatedServiceManifest;
          photonServices = lib.getExe' deploymentCfg.package "photon-services";
          photonCLI = lib.getExe deploymentCfg.package;
          dockerCLI = lib.getExe deploymentCfg.dockerPackage;
          networkComposeFile = "${deploymentCfg.outputDirectory}/networks/docker-compose.yml";
          socks5ComposeFile = "${deploymentCfg.outputDirectory}/socks5/docker-compose.yml";
        in
        {
          options.services.photon = {
            enable = lib.mkEnableOption "Photon mesh daemon";

            package = lib.mkOption {
              type = lib.types.package;
              default = self.packages.${pkgs.stdenv.hostPlatform.system}.default;
              defaultText = lib.literalExpression "self.packages.\${pkgs.stdenv.hostPlatform.system}.default";
              description = "Photon package to run.";
            };

            configFile = lib.mkOption {
              type = lib.types.nullOr lib.types.str;
              default = null;
              example = "/run/secrets/photon/config.yaml";
              description = ''
                Path to an externally managed Photon YAML configuration file.
                This is useful when another deployment system owns the file or
                when it contains values that must not be copied into the Nix
                store. This option and services.photon.settings are mutually
                exclusive. When neither is set, Photon reads
                /etc/photon/config.yaml for backwards compatibility.
              '';
            };

            settings = lib.mkOption {
              type = settingsFormat.type;
              default = { };
              example = lib.literalExpression ''
                {
                  data_dir = "/var/lib/photon";
                  trusted_root_public_key = "base64-public-key";
                  gossip = {
                    peer_id = "node-a.example.";
                    listen_addr = "[::]:33434";
                    bootstrap = [
                      {
                        id = "node-b.example.";
                        addr = "192.0.2.2:33434";
                      }
                    ];
                  };
                  ipsec = {
                    role = "both";
                    driver = "strongswan";
                  };
                }
              '';
              description = ''
                Photon configuration rendered to YAML. Attribute names map
                directly to config.yaml keys; see config.example.yaml in the
                Photon source tree for all supported sections and defaults.
                The generated file is available as /etc/photon/config.yaml and
                backed by the world-readable Nix store, so secret values must
                be referenced by path or supplied through services.photon.configFile
                instead.
              '';
            };

            logLevel = lib.mkOption {
              type = lib.types.nullOr (
                lib.types.enum [
                  "debug"
                  "info"
                  "warn"
                  "error"
                ]
              );
              default = null;
              example = "info";
              description = ''
                Runtime log level set through PHOTON_LOG_LEVEL. A non-null
                value overrides the level in services.photon.settings.log.
              '';
            };

            environment = lib.mkOption {
              type = lib.types.attrsOf lib.types.str;
              default = { };
              example = {
                GODEBUG = "netdns=go";
              };
              description = ''
                Additional environment variables for the Photon service.
                PHOTON_CONFIG is managed by this module and must not be set
                here; use configFile or settings instead.
              '';
            };

            environmentFiles = lib.mkOption {
              type = lib.types.listOf lib.types.str;
              default = [ ];
              example = [ "/run/secrets/photon/environment" ];
              description = ''
                Environment files read by systemd before Photon starts. Prefix
                a path with "-" to make a missing file non-fatal. These files
                can safely provide deployment-specific or secret environment
                values without placing them in the Nix store.
              '';
            };

            runtimePackages = lib.mkOption {
              type = lib.types.listOf lib.types.package;
              default = with pkgs; [
                bird2
                iproute2
                iputils
                ipset
                iptables
                nftables
                procps
                strongswan
              ];
              defaultText = lib.literalExpression ''
                with pkgs; [ bird2 iproute2 iputils ipset iptables nftables procps strongswan ]
              '';
              description = ''
                Packages added to the daemon's PATH for data-plane operations.
                Replace this list to select different implementations, or use
                extraPackages to append tools while retaining the defaults.
              '';
            };

            extraPackages = lib.mkOption {
              type = lib.types.listOf lib.types.package;
              default = [ ];
              example = lib.literalExpression "with pkgs; [ wireguard-tools ]";
              description = "Additional packages added to the Photon service PATH.";
            };

            strongswanService = lib.mkOption {
              type = lib.types.nullOr lib.types.str;
              default = "strongswan.service";
              example = "strongswan-swanctl.service";
              description = ''
                systemd unit that must be started before Photon. Set to null
                for dry-run deployments or when StrongSwan is managed outside
                systemd.
              '';
            };

            openFirewall = lib.mkOption {
              type = lib.types.bool;
              default = false;
              description = ''
                Whether to open Photon ports in the NixOS firewall. This opens
                gossipPort/UDP and, when set, observerPort/TCP. When settings
                contains a non-dry-run ipsec section, it also opens UDP 500,
                UDP 4500, and the configured IPsec port range. For configFile,
                configure ipsecFirewall explicitly because Nix cannot inspect
                the external YAML file.
              '';
            };

            gossipPort = lib.mkOption {
              type = lib.types.port;
              default = 33434;
              description = ''
                UDP gossip port opened when openFirewall is true. Keep this in
                sync with the port in settings.gossip.listen_addr.
              '';
            };

            observerPort = lib.mkOption {
              type = lib.types.nullOr lib.types.port;
              default = null;
              example = 8080;
              description = ''
                TCP observer port opened when openFirewall is true. Keep this
                in sync with settings.observer.listen. Null opens no TCP port.
              '';
            };

            ipsecFirewall = {
              enable = lib.mkOption {
                type = lib.types.bool;
                default = false;
                description = ''
                  Whether openFirewall should open the fixed StrongSwan IKE
                  and NAT-T listener ports, UDP 500 and UDP 4500. This is
                  inferred automatically from services.photon.settings.ipsec.
                  Enable it explicitly when configFile supplies the Photon
                  configuration.
                '';
              };

              portRange = lib.mkOption {
                type = lib.types.nullOr (
                  lib.types.submodule {
                    options = {
                      from = lib.mkOption {
                        type = lib.types.port;
                        example = 33401;
                        description = "First UDP port in the advertised IPsec range.";
                      };
                      to = lib.mkOption {
                        type = lib.types.port;
                        example = 33499;
                        description = "Last UDP port in the advertised IPsec range.";
                      };
                    };
                  }
                );
                default = null;
                example = {
                  from = 33401;
                  to = 33499;
                };
                description = ''
                  UDP range opened for IPsec advertised entry ports. With
                  settings, this is inferred from ipsec.port_range when
                  ipsec.port_mode is range. Set it explicitly when configFile
                  contains a range-mode configuration.
                '';
              };
            };

            serviceDeployment = {
              enable = lib.mkEnableOption "Photon application service deployment";

              package = lib.mkOption {
                type = lib.types.package;
                default = cfg.package;
                defaultText = lib.literalExpression "config.services.photon.package";
                description = "Package providing photon and photon-services.";
              };

              configFile = lib.mkOption {
                type = lib.types.nullOr lib.types.str;
                default = null;
                example = "/run/secrets/photon/service.yaml";
                description = ''
                  Path to an externally managed photon-services manifest. This
                  option and serviceDeployment.settings are mutually exclusive.
                  When neither is set, /etc/photon/service.yaml is used.
                '';
              };

              settings = lib.mkOption {
                type = settingsFormat.type;
                default = { };
                example = lib.literalExpression ''
                  {
                    version = 1;
                    networks.main = {
                      ipv4 = "local;172.30.0.0/24;172.30.0.128/28;172.30.0.1";
                      ipv6 = "auto;::/112;::100/120;::1";
                    };
                    socks5 = {
                      networks.main = "::20";
                      publish.main = "local";
                    };
                  }
                '';
                description = ''
                  photon-services manifest rendered to YAML. Attribute names
                  map directly to service.yaml. The generated file is available
                  as /etc/photon/service.yaml and backed by the world-readable
                  Nix store; use configFile when the manifest contains
                  credentials such as socks5.http_auth.password.
                '';
              };

              outputDirectory = lib.mkOption {
                type = lib.types.str;
                default = "/var/lib/photon/services";
                description = ''
                  Writable directory for generated Compose files, GOST
                  configuration, and resolved/published state. This overrides
                  output_dir in the manifest.
                '';
              };

              dockerPackage = lib.mkOption {
                type = lib.types.package;
                default = pkgs.docker;
                defaultText = lib.literalExpression "pkgs.docker";
                description = "Docker package whose Compose plugin is used.";
              };

              dockerService = lib.mkOption {
                type = lib.types.str;
                default = "docker.service";
                description = "systemd Docker unit required by photon-services.";
              };

              socks5.enable = lib.mkOption {
                type = lib.types.bool;
                default = true;
                description = ''
                  Whether to start the generated SOCKS5 Compose project and
                  publish its service record. Set this to false for a
                  network-only deployment; the systemd target then stops after
                  creating the generated Docker networks.
                '';
              };

              withdrawOnStop = lib.mkOption {
                type = lib.types.bool;
                default = true;
                description = ''
                  Whether to withdraw service records, shared routes, and
                  endpoint ACLs before stopping the containers.
                '';
              };

              stopContainersOnStop = lib.mkOption {
                type = lib.types.bool;
                default = true;
                description = "Whether systemd should run Compose down when the unit stops.";
              };

              restartSec = lib.mkOption {
                type = lib.types.ints.unsigned;
                default = 5;
                description = "Seconds systemd waits before retrying a failed deployment.";
              };

              environment = lib.mkOption {
                type = lib.types.attrsOf lib.types.str;
                default = { };
                description = "Additional environment variables for photon-services and Docker Compose.";
              };

              environmentFiles = lib.mkOption {
                type = lib.types.listOf lib.types.str;
                default = [ ];
                example = [ "/run/secrets/photon-services/environment" ];
                description = "Environment files read by the photon-services systemd unit.";
              };

              extraServiceConfig = lib.mkOption {
                type = lib.types.attrsOf lib.types.anything;
                default = { };
                description = "Additional or overriding systemd serviceConfig values.";
              };
            };

            user = lib.mkOption {
              type = lib.types.str;
              default = "root";
              description = ''
                User account used to run Photon. Real network namespace, XFRM,
                routing, and firewall reconciliation normally require root.
              '';
            };

            group = lib.mkOption {
              type = lib.types.str;
              default = "root";
              description = "Group used to run Photon.";
            };

            restartPolicy = lib.mkOption {
              type = lib.types.enum [
                "no"
                "on-success"
                "on-failure"
                "on-abnormal"
                "on-abort"
                "on-watchdog"
                "always"
              ];
              default = "on-failure";
              description = "systemd restart policy for the Photon daemon.";
            };

            restartSec = lib.mkOption {
              type = lib.types.ints.unsigned;
              default = 2;
              description = "Seconds systemd waits before restarting Photon.";
            };

            extraServiceConfig = lib.mkOption {
              type = lib.types.attrsOf lib.types.anything;
              default = { };
              example = {
                Nice = 5;
                OOMScoreAdjust = -250;
              };
              description = ''
                Additional or overriding values for the systemd serviceConfig
                attribute set. Use this for deployment-specific limits and
                sandboxing settings.
              '';
            };
          };

          config = lib.mkMerge [
            (lib.mkIf cfg.enable {
              assertions = [
                {
                  assertion = cfg.configFile == null || cfg.settings == { };
                  message = ''
                    services.photon.configFile and services.photon.settings cannot
                    be used together; choose an external file or generated YAML.
                  '';
                }
                {
                  assertion = !(cfg.environment ? PHOTON_CONFIG);
                  message = ''
                    services.photon.environment.PHOTON_CONFIG is managed by the
                    module; use services.photon.configFile or settings instead.
                  '';
                }
                {
                  assertion = cfg.logLevel == null || !(cfg.environment ? PHOTON_LOG_LEVEL);
                  message = ''
                    Set the log level with either services.photon.logLevel or
                    services.photon.environment.PHOTON_LOG_LEVEL, not both.
                  '';
                }
                {
                  assertion =
                    !(cfg.openFirewall && inferIPsecFirewall && settingsIPsecPortMode == "range")
                    || validPortRange settingsIPsecPortRange;
                  message = ''
                    services.photon.settings.ipsec.port_mode is "range", so
                    settings.ipsec.port_range must contain valid from/to ports
                    with from less than or equal to to.
                  '';
                }
                {
                  assertion =
                    cfg.ipsecFirewall.portRange == null
                    || cfg.ipsecFirewall.portRange.from <= cfg.ipsecFirewall.portRange.to;
                  message = ''
                    services.photon.ipsecFirewall.portRange.from must be less
                    than or equal to portRange.to.
                  '';
                }
                {
                  assertion =
                    cfg.configFile == null || cfg.ipsecFirewall.portRange == null || cfg.ipsecFirewall.enable;
                  message = ''
                    services.photon.ipsecFirewall.enable must be true when an
                    explicit portRange is used with configFile.
                  '';
                }
              ];

              networking.firewall.allowedUDPPorts = lib.unique (
                lib.optional cfg.openFirewall cfg.gossipPort
                ++ lib.optionals openIPsecFirewall [
                  500
                  4500
                ]
              );
              networking.firewall.allowedUDPPortRanges =
                lib.optional (openIPsecFirewall && validPortRange effectiveIPsecPortRange)
                  {
                    inherit (effectiveIPsecPortRange) from to;
                  };
              networking.firewall.allowedTCPPorts = lib.optional (
                cfg.openFirewall && cfg.observerPort != null
              ) cfg.observerPort;

              environment.etc."photon/config.yaml" = lib.mkIf (cfg.configFile == null && cfg.settings != { }) {
                source = generatedConfig;
              };

              systemd.services.photon = {
                description = "Photon mesh daemon";
                wantedBy = [ "multi-user.target" ];
                restartTriggers = generatedConfigRestartTriggers;
                wants = [
                  "network-online.target"
                ]
                ++ lib.optional (cfg.strongswanService != null) cfg.strongswanService;
                after = [
                  "network-online.target"
                ]
                ++ lib.optional (cfg.strongswanService != null) cfg.strongswanService;
                environment =
                  cfg.environment
                  // {
                    PHOTON_CONFIG = configFile;
                  }
                  // lib.optionalAttrs (cfg.logLevel != null) {
                    PHOTON_LOG_LEVEL = cfg.logLevel;
                  };
                path = cfg.runtimePackages ++ cfg.extraPackages;
                serviceConfig = {
                  Type = "simple";
                  User = cfg.user;
                  Group = cfg.group;
                  ExecStart = "${lib.getExe cfg.package} daemon";
                  Restart = cfg.restartPolicy;
                  RestartMode = "direct";
                  RestartSec = cfg.restartSec;
                  TimeoutStopSec = 30;
                  RuntimeDirectory = "photon";
                  RuntimeDirectoryMode = "0700";
                  UMask = "0077";
                  LimitNOFILE = 65536;
                  EnvironmentFile = cfg.environmentFiles;
                }
                // cfg.extraServiceConfig;
              };
            })

            (lib.mkIf deploymentCfg.enable {
              assertions = [
                {
                  assertion = cfg.enable;
                  message = ''
                    services.photon.serviceDeployment requires
                    services.photon.enable because render and publish query the
                    running Photon daemon.
                  '';
                }
                {
                  assertion = deploymentCfg.configFile == null || deploymentCfg.settings == { };
                  message = ''
                    services.photon.serviceDeployment.configFile and settings
                    cannot be used together; choose an external manifest or
                    generated YAML.
                  '';
                }
                {
                  assertion = lib.hasPrefix "/" deploymentCfg.outputDirectory;
                  message = "services.photon.serviceDeployment.outputDirectory must be an absolute path.";
                }
                {
                  assertion = !(deploymentCfg.environment ? PHOTON_CONFIG);
                  message = ''
                    serviceDeployment.environment.PHOTON_CONFIG is managed by
                    the module and inherited from the Photon daemon config.
                  '';
                }
                {
                  assertion =
                    deploymentCfg.configFile != null
                    || deploymentCfg.settings == { }
                    || !deploymentCfg.socks5.enable
                    || (deploymentCfg.settings ? socks5 && deploymentCfg.settings.socks5 != { });
                  message = ''
                    services.photon.serviceDeployment.socks5.enable is true,
                    but the generated manifest has no socks5 configuration;
                    configure settings.socks5 or set socks5.enable to false.
                  '';
                }
              ];

              virtualisation.docker.enable = lib.mkDefault true;

              environment.etc."photon/service.yaml" = lib.mkIf (
                deploymentCfg.configFile == null && deploymentCfg.settings != { }
              ) {
                source = generatedServiceManifest;
              };

              systemd.targets.photon-services = {
                description = "Photon application services";
                wantedBy = [ "multi-user.target" ];
                requires = [
                  (
                    if deploymentCfg.socks5.enable then
                      "photon-services-publish.service"
                    else
                      "photon-services-networks.service"
                  )
                ];
                after = [
                  (
                    if deploymentCfg.socks5.enable then
                      "photon-services-publish.service"
                    else
                      "photon-services-networks.service"
                  )
                ];
              };

              systemd.services = {
                photon-services-render = {
                  description = "Render Photon application service artifacts";
                  partOf = [ "photon-services.target" ];
                  restartTriggers = generatedServiceManifestRestartTriggers;
                  requires = [ "photon.service" ];
                  after = [ "photon.service" ];
                  before = [ "photon-services-networks.service" ];
                  environment = deploymentCfg.environment // {
                    PHOTON_CONFIG = configFile;
                  };
                  path = [
                    deploymentCfg.package
                    pkgs.coreutils
                  ];
                  script = ''
                    set -euo pipefail
                    install -d -m 0750 ${lib.escapeShellArg deploymentCfg.outputDirectory}
                    ${photonServices} render \
                      --config ${lib.escapeShellArg serviceManifestFile} \
                      --photon ${lib.escapeShellArg photonCLI} \
                      --output ${lib.escapeShellArg deploymentCfg.outputDirectory}
                  '';
                  serviceConfig = {
                    Type = "oneshot";
                    RemainAfterExit = true;
                    User = "root";
                    Group = "root";
                    Restart = "on-failure";
                    RestartMode = "direct";
                    RestartSec = deploymentCfg.restartSec;
                    TimeoutStartSec = 120;
                    UMask = "0027";
                    EnvironmentFile = deploymentCfg.environmentFiles;
                  }
                  // deploymentCfg.extraServiceConfig;
                };

                photon-services-networks = {
                  description = "Manage Photon Docker networks";
                  partOf = [ "photon-services.target" ];
                  restartTriggers = generatedServiceManifestRestartTriggers;
                  requires = [
                    deploymentCfg.dockerService
                    "photon-services-render.service"
                  ];
                  after = [
                    deploymentCfg.dockerService
                    "photon-services-render.service"
                  ];
                  before = lib.optional deploymentCfg.socks5.enable "photon-services-socks5.service";
                  environment = deploymentCfg.environment;
                  path = [ deploymentCfg.dockerPackage ];
                  script = ''
                    set -euo pipefail
                    ${dockerCLI} compose --file ${lib.escapeShellArg networkComposeFile} up --detach || {
                      ${dockerCLI} compose --file ${lib.escapeShellArg networkComposeFile} down || true
                      exit 1
                    }
                  '';
                  preStop = lib.optionalString deploymentCfg.stopContainersOnStop ''
                    ${dockerCLI} compose --file ${lib.escapeShellArg networkComposeFile} down
                  '';
                  serviceConfig = {
                    Type = "oneshot";
                    RemainAfterExit = true;
                    User = "root";
                    Group = "root";
                    Restart = "on-failure";
                    RestartMode = "direct";
                    RestartSec = deploymentCfg.restartSec;
                    TimeoutStartSec = 300;
                    TimeoutStopSec = 120;
                    UMask = "0027";
                    EnvironmentFile = deploymentCfg.environmentFiles;
                  }
                  // deploymentCfg.extraServiceConfig;
                };
              }
              // lib.optionalAttrs deploymentCfg.socks5.enable {

                photon-services-socks5 = {
                  description = "Manage Photon SOCKS5 containers";
                  partOf = [ "photon-services.target" ];
                  restartTriggers = generatedServiceManifestRestartTriggers;
                  requires = [
                    deploymentCfg.dockerService
                    "photon-services-networks.service"
                  ];
                  after = [
                    deploymentCfg.dockerService
                    "photon-services-networks.service"
                  ];
                  before = [ "photon-services-publish.service" ];
                  environment = deploymentCfg.environment;
                  path = [ deploymentCfg.dockerPackage ];
                  script = ''
                    set -euo pipefail
                    ${dockerCLI} compose --file ${lib.escapeShellArg socks5ComposeFile} up --detach --remove-orphans || {
                      ${dockerCLI} compose --file ${lib.escapeShellArg socks5ComposeFile} down || true
                      exit 1
                    }
                  '';
                  preStop = lib.optionalString deploymentCfg.stopContainersOnStop ''
                    ${dockerCLI} compose --file ${lib.escapeShellArg socks5ComposeFile} down
                  '';
                  serviceConfig = {
                    Type = "oneshot";
                    RemainAfterExit = true;
                    User = "root";
                    Group = "root";
                    Restart = "on-failure";
                    RestartMode = "direct";
                    RestartSec = deploymentCfg.restartSec;
                    TimeoutStartSec = 300;
                    TimeoutStopSec = 120;
                    UMask = "0027";
                    EnvironmentFile = deploymentCfg.environmentFiles;
                  }
                  // deploymentCfg.extraServiceConfig;
                };

                photon-services-publish = {
                  description = "Publish Photon application services";
                  partOf = [ "photon-services.target" ];
                  restartTriggers = generatedServiceManifestRestartTriggers;
                  requires = [
                    "photon.service"
                    "photon-services-socks5.service"
                  ];
                  after = [
                    "photon.service"
                    "photon-services-socks5.service"
                  ];
                  environment = deploymentCfg.environment // {
                    PHOTON_CONFIG = configFile;
                  };
                  path = [ deploymentCfg.package ];
                  script = ''
                    set -euo pipefail
                    ${photonServices} publish \
                      --config ${lib.escapeShellArg serviceManifestFile} \
                      --photon ${lib.escapeShellArg photonCLI} \
                      --output ${lib.escapeShellArg deploymentCfg.outputDirectory}
                  '';
                  preStop = lib.optionalString deploymentCfg.withdrawOnStop ''
                    ${photonServices} withdraw \
                      --config ${lib.escapeShellArg serviceManifestFile} \
                      --photon ${lib.escapeShellArg photonCLI} \
                      --output ${lib.escapeShellArg deploymentCfg.outputDirectory}
                  '';
                  serviceConfig = {
                    Type = "oneshot";
                    RemainAfterExit = true;
                    User = "root";
                    Group = "root";
                    Restart = "on-failure";
                    RestartMode = "direct";
                    RestartSec = deploymentCfg.restartSec;
                    TimeoutStartSec = 120;
                    TimeoutStopSec = 120;
                    UMask = "0027";
                    EnvironmentFile = deploymentCfg.environmentFiles;
                  }
                  // deploymentCfg.extraServiceConfig;
                };
              };
            })
          ];
        };

      devShells = forAllSystems (
        system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
        in
        {
          default = pkgs.mkShell {
            packages = [
              pkgs.bird2
              pkgs.go
              pkgs.gopls
              pkgs.iproute2
              pkgs.ipset
              pkgs.iptables
              pkgs.nftables
              pkgs.strongswan
              pkgs.wireguard-tools
            ];
          };
        }
      );
    };
}
