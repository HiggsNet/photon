.PHONY: all build clean test test-verbose fmt vet check install run photon-windows-build photon-windows-cross-build photon-windows-test smoke smoke-all root-smoke join-smoke zone-sort-smoke record-view-smoke cli-surface-smoke phase1-smoke phase2-smoke phase2-run-smoke phase3-daemon-smoke phase3-daemon-fallback-smoke admin-daemon-smoke multi-node-smoke chain-relay-smoke discovery-smoke reflector-smoke bootstrap-join-smoke nat-observed-smoke nat-daemon-observed-smoke delegation-revoke-smoke object-pull-smoke chunk-fallback-smoke ipsec-policy-smoke ipsec-dry-run-smoke routing-dry-run-smoke firewall-dry-run-smoke firewall-smoke firewall-container-smoke health-smoke health-fault-smoke health-fault-container-smoke services-smoke peer-lifecycle-smoke revocation-cleanup-smoke revocation-data-plane-smoke revocation-data-plane-container-smoke observer-smoke ipsec-xfrm-preflight ipsec-xfrm-smoke ipsec-xfrm-container-smoke bird-babel-preflight bird-babel-smoke bird-babel-container-smoke phase7-1-bird-experiment phase7-1-wg-gre-experiment release-check release-tag release-push help

BINARY_NAME := photon
MAIN_PACKAGE := ./app/photon
SERVICES_BINARY_NAME := photon-services
SERVICES_MAIN_PACKAGE := ./app/photon-services
PHOTON_WINDOWS_BINARY_NAME := photon-windows.exe
PHOTON_WINDOWS_MAIN_PACKAGE := ./app/photon-windows
BUILD_DIR := build
GO := go
GO_CACHE ?= /tmp/photon-gocache
GO_MOD_CACHE ?= /tmp/photon-gomodcache
DOCKER ?= docker
DOCKER_IMAGE ?= photon:dev
RELEASE_REMOTE ?= origin
RELEASE_VERSION := $(shell tr -d '\r\n' < VERSION 2>/dev/null)
RELEASE_TAG := v$(RELEASE_VERSION)
GIT_COMMIT := $(shell git rev-parse --short=12 HEAD 2>/dev/null || echo unknown)
GIT_DESCRIBE := $(shell git describe --tags --always --dirty 2>/dev/null || echo unknown)
GIT_DIRTY := $(shell test -n "$$(git status --porcelain 2>/dev/null)" && echo true || echo false)
BUILD_TIME := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

# Build flags
LDFLAGS := -s -w -X main.buildCommit=$(GIT_COMMIT) -X main.buildDescribe=$(GIT_DESCRIBE) -X main.buildDirty=$(GIT_DIRTY) -X main.buildTime=$(BUILD_TIME)
CGO_ENABLED := 0
GO_ENV := GOCACHE=$(GO_CACHE) GOMODCACHE=$(GO_MOD_CACHE) CGO_ENABLED=$(CGO_ENABLED)
WINDOWS_GO_MOD_CACHE ?= /tmp/photon-windows-gomodcache
WINDOWS_AMD64_GO_ENV := GOCACHE=$(GO_CACHE) GOMODCACHE=$(WINDOWS_GO_MOD_CACHE) CGO_ENABLED=0 GOOS=windows GOARCH=amd64
SMOKE_TARGETS := join-smoke zone-sort-smoke record-view-smoke cli-surface-smoke phase1-smoke phase2-smoke phase2-run-smoke phase3-daemon-smoke phase3-daemon-fallback-smoke admin-daemon-smoke multi-node-smoke chain-relay-smoke discovery-smoke reflector-smoke bootstrap-join-smoke nat-observed-smoke nat-daemon-observed-smoke delegation-revoke-smoke object-pull-smoke chunk-fallback-smoke ipsec-policy-smoke ipsec-dry-run-smoke routing-dry-run-smoke firewall-dry-run-smoke peer-lifecycle-smoke revocation-cleanup-smoke observer-smoke
ROOT_SMOKE_TARGETS := ipsec-xfrm-smoke bird-babel-smoke firewall-smoke health-fault-smoke
ISOLATED_SMOKE_TARGETS := smoke smoke-all root-smoke $(SMOKE_TARGETS) $(ROOT_SMOKE_TARGETS)

# Every smoke invocation gets a private TMPDIR and derives one control socket per
# test data_dir. This is especially important under sudo: root otherwise defaults
# to the live /run/photon/photon.sock and a smoke mutation can reach production state.
ifneq ($(strip $(filter $(ISOLATED_SMOKE_TARGETS),$(MAKECMDGOALS))),)
SMOKE_TMP_BASE := $(if $(TMPDIR),$(TMPDIR),/tmp)
SMOKE_RUN_DIR := $(shell mktemp -d "$(SMOKE_TMP_BASE)/photon-smoke.XXXXXX")
ifeq ($(strip $(SMOKE_RUN_DIR)),)
$(error failed to create isolated smoke directory below $(SMOKE_TMP_BASE))
endif
$(ISOLATED_SMOKE_TARGETS): export TMPDIR := $(SMOKE_RUN_DIR)
$(ISOLATED_SMOKE_TARGETS): export PHOTON_CONTROL_SOCKET :=
$(ISOLATED_SMOKE_TARGETS): export PHOTON_CONTROL_SOCKET_SCOPE := data-dir
$(ISOLATED_SMOKE_TARGETS): export PHOTON_STATE :=
endif

.PHONY: docker-build docker-run-example nix-build install-script-check

all: build

build:
	@mkdir -p $(BUILD_DIR)
	$(GO_ENV) $(GO) build -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME) $(MAIN_PACKAGE)
	$(GO_ENV) $(GO) build -o $(BUILD_DIR)/$(SERVICES_BINARY_NAME) $(SERVICES_MAIN_PACKAGE)
	@echo "Built: $(BUILD_DIR)/$(BINARY_NAME) and $(BUILD_DIR)/$(SERVICES_BINARY_NAME)"

clean:
	@rm -rf $(BUILD_DIR)
	@echo "Cleaned build artifacts"

test:
	$(GO_ENV) $(GO) test ./...

test-verbose:
	$(GO_ENV) $(GO) test -v ./...

fmt:
	$(GO_ENV) $(GO) fmt ./...

vet:
	$(GO_ENV) $(GO) vet ./...

check: fmt vet test build photon-windows-cross-build

photon-windows-build: photon-windows-cross-build

photon-windows-cross-build:
	@mkdir -p $(BUILD_DIR)/windows-amd64
	$(WINDOWS_AMD64_GO_ENV) $(GO) build -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/windows-amd64/$(PHOTON_WINDOWS_BINARY_NAME) $(PHOTON_WINDOWS_MAIN_PACKAGE)
	$(WINDOWS_AMD64_GO_ENV) $(GO) build ./internal/photonwindows ./internal/photonclient/ike ./internal/photonclient/esp ./pkg/core/host ./pkg/core/state ./pkg/core/zone ./pkg/core/gossip ./pkg/crypto ./pkg/routing ./pkg/transport/ipsec
	@cp -R third_party $(BUILD_DIR)/windows-amd64/
	@echo "Built: $(BUILD_DIR)/windows-amd64/$(PHOTON_WINDOWS_BINARY_NAME)"

photon-windows-test:
	$(GO_ENV) $(GO) test ./internal/photonwindows ./internal/photonclient/ike ./internal/photonclient/esp $(PHOTON_WINDOWS_MAIN_PACKAGE)

install:
	$(GO_ENV) $(GO) install $(MAIN_PACKAGE)
	$(GO_ENV) $(GO) install $(SERVICES_MAIN_PACKAGE)

install-script-check:
	@sh -n contrib/install.sh contrib/update.sh contrib/photon-admin
	@contrib/install.sh --help | grep -q -- '--admin'
	@grep -q 'install_admin=false' contrib/install.sh
	@grep -q 'if \[ "$$install_admin" = true \]; then' contrib/install.sh
	@grep -Fq 'if ! sudo test -e "$$admin_config" && ! sudo test -L "$$admin_config"; then' contrib/install.sh
	@if grep -Fq '[ -e "$$admin_config" ] || sudo install' contrib/install.sh; then \
		echo 'admin config existence must be checked through sudo' >&2; exit 1; \
	fi
	@grep -q 'Environment=PHOTON_STATE=/etc/photon/photon.db' contrib/systemd/photon.service
	@grep -q 'Environment=PHOTON_ADMIN_CONFIG=/etc/photon/admin/config.yaml' contrib/systemd/photon-admin.service
	@grep -q 'Environment=PHOTON_ADMIN_STATE=/etc/photon/admin/photon.db' contrib/systemd/photon-admin.service
	@grep -q 'Environment=PHOTON_ADMIN_CONTROL_SOCKET=/run/photon-admin/photon.sock' contrib/systemd/photon-admin.service
	@grep -q 'exec "$${PHOTON_ADMIN_BINARY:-$${script_dir}/photon}" "$$@"' contrib/photon-admin
	@output="$$(PHOTON_CONFIG=wrong PHOTON_STATE=wrong PHOTON_CONTROL_SOCKET=wrong PHOTON_ADMIN_BINARY=env contrib/photon-admin)"; \
	printf '%s\n' "$$output" | grep -qx 'PHOTON_CONFIG=/etc/photon/admin/config.yaml'; \
	printf '%s\n' "$$output" | grep -qx 'PHOTON_STATE=/etc/photon/admin/photon.db'; \
	printf '%s\n' "$$output" | grep -qx 'PHOTON_CONTROL_SOCKET=/run/photon-admin/photon.sock'
	@output="$$(mktemp)"; trap 'rm -f "$$output"' EXIT HUP INT TERM; \
	PHOTON_SKIP_DEPENDENCY_CHECK=invalid contrib/install.sh --version test --no-service >"$$output" 2>&1; \
	status=$$?; test "$$status" -eq 2; \
	grep -q 'PHOTON_SKIP_DEPENDENCY_CHECK must be true or false' "$$output"

run: build
	$(BUILD_DIR)/$(BINARY_NAME)

docker-build:
	$(DOCKER) build \
		--build-arg VERSION="$(GIT_DESCRIBE)" \
		--build-arg COMMIT="$(GIT_COMMIT)" \
		--build-arg DIRTY="$(GIT_DIRTY)" \
		--build-arg BUILD_TIME="$(BUILD_TIME)" \
		-t "$(DOCKER_IMAGE)" .

docker-run-example:
	$(DOCKER) run --rm --privileged --network host \
		-v "$${PWD}/docker/config.example.yaml:/etc/photon/config.yaml:ro" \
		-v "$${PWD}/.photon:/var/lib/photon" \
		"$(DOCKER_IMAGE)" version

nix-build:
	nix build .#photon

# Release flow: first make release-check, then make release-tag, then
# make release-push. Neither target commits nor pushes the current branch.
release-check:
	@test -n "$(RELEASE_VERSION)" || { echo "VERSION is empty or missing" >&2; exit 1; }
	@printf '%s\n' "$(RELEASE_VERSION)" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$$' || { echo "VERSION must be MAJOR.MINOR.PATCH, got $(RELEASE_VERSION)" >&2; exit 1; }
	@git diff --check
	@test -z "$$(git status --porcelain)" || { echo "working tree must be clean before release" >&2; git status --short >&2; exit 1; }
	@if git rev-parse -q --verify "refs/tags/$(RELEASE_TAG)" >/dev/null; then echo "tag $(RELEASE_TAG) already exists locally" >&2; exit 1; fi
	@upstream="$$(git rev-parse --abbrev-ref --symbolic-full-name '@{upstream}' 2>/dev/null)" || { echo "current branch has no upstream" >&2; exit 1; }; \
	git merge-base --is-ancestor HEAD "$$upstream" || { echo "HEAD has not been pushed to $$upstream" >&2; exit 1; }
	@$(MAKE) test vet build
	@echo "Release checks passed for $(RELEASE_TAG)"

release-tag: release-check
	@git tag -a "$(RELEASE_TAG)" -m "$(RELEASE_TAG)"
	@echo "Created local tag $(RELEASE_TAG). Run 'make release-push' to publish it."

release-push:
	@git rev-parse -q --verify "refs/tags/$(RELEASE_TAG)" >/dev/null || { echo "local tag $(RELEASE_TAG) does not exist; run 'make release-tag' first" >&2; exit 1; }
	@tag_commit="$$(git rev-parse "$(RELEASE_TAG)^{commit}")"; head_commit="$$(git rev-parse HEAD)"; \
	test "$$tag_commit" = "$$head_commit" || { echo "tag $(RELEASE_TAG) does not point to HEAD" >&2; exit 1; }
	@git push "$(RELEASE_REMOTE)" "$(RELEASE_TAG)"
	@echo "Pushed $(RELEASE_TAG) to $(RELEASE_REMOTE); GitHub Release will now run."

smoke: smoke-all

smoke-all: $(SMOKE_TARGETS)
	@echo "All smoke tests passed"
	@rm -rf "$(SMOKE_RUN_DIR)"

root-smoke: $(ROOT_SMOKE_TARGETS)
	@PHOTON_REVOCATION_DATA_PLANE_SKIP_SHARED=1 GO="$(GO)" GOCACHE="$(GO_CACHE)" GOMODCACHE="$(GO_MOD_CACHE)" CGO_ENABLED="$(CGO_ENABLED)" docs/scripts/revocation-data-plane-smoke.sh
	@echo "All root data-plane smoke tests passed"
	@rm -rf "$(SMOKE_RUN_DIR)"

ipsec-xfrm-preflight:
	@docs/scripts/ipsec-xfrm-preflight.sh

ipsec-xfrm-smoke: build
	@GO="$(GO)" GOCACHE="$(GO_CACHE)" GOMODCACHE="$(GO_MOD_CACHE)" CGO_ENABLED="$(CGO_ENABLED)" docs/scripts/ipsec-xfrm-smoke.sh

ipsec-xfrm-container-smoke:
	@GO="$(GO)" GOCACHE="$(GO_CACHE)" GOMODCACHE="$(GO_MOD_CACHE)" CGO_ENABLED="$(CGO_ENABLED)" docs/scripts/ipsec-xfrm-container-smoke.sh

bird-babel-preflight:
	@docs/scripts/bird-babel-preflight.sh

bird-babel-smoke: build
	@GO="$(GO)" GOCACHE="$(GO_CACHE)" GOMODCACHE="$(GO_MOD_CACHE)" CGO_ENABLED="$(CGO_ENABLED)" docs/scripts/bird-babel-smoke.sh

phase7-1-bird-experiment: build
	@GO="$(GO)" GOCACHE="$(GO_CACHE)" GOMODCACHE="$(GO_MOD_CACHE)" CGO_ENABLED="$(CGO_ENABLED)" docs/scripts/phase7-1-bird-experiment.sh

phase7-1-wg-gre-experiment: build
	@GO="$(GO)" GOCACHE="$(GO_CACHE)" GOMODCACHE="$(GO_MOD_CACHE)" CGO_ENABLED="$(CGO_ENABLED)" WG="$(WG)" docs/scripts/phase7-1-wg-gre-experiment.sh

bird-babel-container-smoke:
	@GO="$(GO)" GOCACHE="$(GO_CACHE)" GOMODCACHE="$(GO_MOD_CACHE)" CGO_ENABLED="$(CGO_ENABLED)" docs/scripts/bird-babel-container-smoke.sh

ipsec-dry-run-smoke:
	$(GO_ENV) $(GO) test ./pkg/transport/ipsec
	@echo "IPsec dry-run smoke passed"

routing-dry-run-smoke:
	$(GO_ENV) $(GO) test ./app/photon -run 'Test(RoutingDryRunSmoke|IPAMRoutingSmoke|AutoAnnounceAssignedIPsRoutingSmoke)' -v
	@echo "Routing dry-run smoke passed"

ipsec-policy-smoke:
	$(GO_ENV) $(GO) test ./pkg/transport/ipsec -run 'Test(ParseMeshPolicy|PlanTransportLinksAppliesMeshPolicyRules)'
	@echo "IPsec policy smoke passed"

firewall-dry-run-smoke:
	$(GO_ENV) $(GO) test ./pkg/firewall
	$(GO_ENV) $(GO) test ./app/photon -run 'Test(ParseConfigYAMLFirewall|TestFirewallInstancesEnabled|TestFirewallInstanceSpecFromConfig|TestReconcileFirewall|TestDebugFirewall)' -v
	$(GO_ENV) $(GO) test ./internal/inspect/text -run '^TestWriteFirewall' -v
	@echo "Firewall dry-run smoke passed"

firewall-smoke: build
	@PHOTON_FIREWALL_SMOKE=1 $(GO_ENV) $(GO) test ./pkg/firewall -run 'TestFirewallBackendsRootSmoke' -count=1 -v
	@echo "Firewall root smoke passed"

firewall-container-smoke:
	@GO="$(GO)" GOCACHE="$(GO_CACHE)" GOMODCACHE="$(GO_MOD_CACHE)" CGO_ENABLED="$(CGO_ENABLED)" docs/scripts/firewall-container-smoke.sh

health-smoke: build
	$(GO_ENV) $(GO) test ./pkg/health -run 'Test(Manager|RollingWindow|StateMachine|ICMProber|RawICMProber|CollectMetricsAndRender)' -v
	$(GO_ENV) $(GO) test ./app/photon -run 'Test(HealthTargets|ConfigureHealthManager|HealthStatusAndSpool|HealthLocalSpool|ReconcileRoutingFeedsBirdObservationToRotateCutoverGate)' -v
	@docs/scripts/bird-babel-preflight.sh
	@PHOTON_HEALTH_SMOKE=1 $(GO_ENV) $(GO) test ./app/photon -run '^TestDaemonHealthBIRDCutoverGateRootSmoke$$' -count=1 -v
	@echo "Health root smoke passed"

health-fault-smoke: health-smoke
	@echo "Health fault-injection smoke passed"

health-fault-container-smoke:
	@GO="$(GO)" GOCACHE="$(GO_CACHE)" GOMODCACHE="$(GO_MOD_CACHE)" CGO_ENABLED="$(CGO_ENABLED)" docs/scripts/health-fault-container-smoke.sh

services-smoke: build
	$(GO_ENV) $(GO) test ./app/photon-services -count=1 -v
	@PHOTON_SERVICES_SMOKE=1 $(GO_ENV) $(GO) test ./app/photon-services -run '^TestSOCKS5DockerBridgeBabelRootSmoke$$' -count=1 -v
	@PHOTON_BIRD_SMOKE=1 $(GO_ENV) $(GO) test ./pkg/routing/bird -run '^TestBabelAnycastFailoverRootSmoke$$' -count=1 -v
	@echo "Phase 8 services root smoke passed"

peer-lifecycle-smoke:
	$(GO_ENV) $(GO) test ./app/photon -run 'TestDerivePeerStatus|TestPeerStatus|TestShouldBlockReconnect|TestCollectRevokedPeerZones|TestParsePeerLifecycleConfig|TestWriteDebugPeers|TestRevokedLinkPeers|TestDaemonRemoteAppliedEventUpdatesPeerState' -v
	@echo "Peer lifecycle smoke passed"

revocation-cleanup-smoke:
	$(GO_ENV) $(GO) test ./app/photon -run 'TestRevocation|TestCollectAllRevokedZones|TestCleanupRevokedPeerCache|TestConfiguredBootstrapPeerRevoked|TestWriteRevocationImpacts|TestDaemonFlushRevocationCleanup|TestDaemonRevocationCleanupPeerCache|TestDaemonRevocationTearsDownIPsecLinkAndBlocksRecreate' -v
	@echo "Revocation cleanup smoke passed"

revocation-data-plane-smoke: build
	@GO="$(GO)" GOCACHE="$(GO_CACHE)" GOMODCACHE="$(GO_MOD_CACHE)" CGO_ENABLED="$(CGO_ENABLED)" docs/scripts/revocation-data-plane-smoke.sh

revocation-data-plane-container-smoke:
	@GO="$(GO)" GOCACHE="$(GO_CACHE)" GOMODCACHE="$(GO_MOD_CACHE)" CGO_ENABLED="$(CGO_ENABLED)" docs/scripts/revocation-data-plane-container-smoke.sh

observer-smoke:
	$(GO_ENV) $(GO) test ./app/photon -run 'Test(ParseObserverConfig|ObserverConfig|SSEHub|Observer(Status|Handler|Zones|Peers|Links|Health|Routes|Bird|Events|Static|StartObserver|NotifyObserver)|Web(SubFS|AppEscapesHTML|AppPreservesFoldState))' -v
	@echo "Observer smoke passed"

# Smoke 目标约定：
# - 每个 smoke 都在 $TMPDIR 下创建独立目录，避免重复运行时复用密钥、
#   bbolt 状态、sync peer 元数据或残留 control socket。
# - 信任链必须显式表达：root admin 只管理 "."；catofes. 是被 root 委派
#   的管理 Zone；普通节点再由 catofes. 委派。
# - 现代 gossip peer_id 应默认等于节点管理的 Zone FQDN，例如
#   node-a.catofes.；仍使用短 peer_id 的旧目标只保留兼容性检查语义。
# - 非 root 配置都写入 trusted_root_public_key，使测试能捕获错误 root 或
#   缺失 root 状态，而不是误信任本地 authority。
# - 部分 sync-once smoke 会允许 "pending zones" 后再断言最终状态：
#   sync once 不能在对端还有对象待拉取时宣称完全收敛，但当前单向传输
#   目标本身可能已经成功。

# join-smoke 流程：
# 1. 创建隔离的 root admin、catofes 管理端和 node-b 数据目录。
# 2. root admin 初始化 "."，catofes. 生成 join request 并由 root 签发 delegation。
# 3. catofes. 导入 bundle 成为管理 Zone；root 再通过 delegate grant 追加
#    allocate-ip，catofes. 接受 refresh bundle。
# 4. catofes. 为 node-b.catofes. 签发 leaf delegation。
# 5. node-b 导入 bundle，写入 identity record，并用 verify 检查本地信任链。
# 6. 该目标不启动 UDP，只验证离线准入、权限、密钥、bundle 和本地持久化。
join-smoke: build
	@set -eu; \
	tmp="$${TMPDIR:-/tmp}/photon-join-smoke"; \
	rm -rf "$$tmp"; \
	mkdir -p "$$tmp/admin" "$$tmp/catofes" "$$tmp/node-b"; \
	printf '%s\n' 'data_dir: '"$$tmp/admin" 'gossip:' '  peer_id: node-admin' '  listen_addr: 127.0.0.1:43433' > "$$tmp/admin/config.yaml"; \
	printf '%s\n' 'data_dir: '"$$tmp/catofes" 'gossip:' '  peer_id: zone-catofes-admin' '  listen_addr: 127.0.0.1:43434' > "$$tmp/catofes/config.yaml"; \
	printf '%s\n' 'data_dir: '"$$tmp/node-b" 'gossip:' '  peer_id: node-b' '  listen_addr: 127.0.0.1:43435' > "$$tmp/node-b/config.yaml"; \
	PHOTON_CONFIG="$$tmp/admin/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip root init >/dev/null; \
	PHOTON_CONFIG="$$tmp/catofes/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip keygen "$$tmp/catofes.key.json" >/dev/null; \
	PHOTON_CONFIG="$$tmp/catofes/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip join request catofes. "$$tmp/catofes.key.json" "$$tmp/catofes.request.json" >/dev/null; \
	PHOTON_CONFIG="$$tmp/admin/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip delegate issue --direct --permissions write,delegate "$$tmp/catofes.request.json" "$$tmp/catofes.bundle.json" >/dev/null; \
	PHOTON_CONFIG="$$tmp/catofes/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip join accept --direct "$$tmp/catofes.bundle.json" "$$tmp/catofes.key.json" >/dev/null; \
	if PHOTON_CONFIG="$$tmp/catofes/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip zone show catofes. | grep -q 'allocate-ip'; then exit 1; fi; \
	PHOTON_CONFIG="$$tmp/admin/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip delegate grant --direct catofes. allocate-ip "$$tmp/catofes.grant.json" >/dev/null; \
	PHOTON_CONFIG="$$tmp/catofes/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip join accept --direct "$$tmp/catofes.grant.json" >/dev/null; \
	PHOTON_CONFIG="$$tmp/catofes/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip zone show catofes. | grep -q 'allocate-ip'; \
	PHOTON_CONFIG="$$tmp/node-b/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip keygen "$$tmp/node-b.key.json" >/dev/null; \
	PHOTON_CONFIG="$$tmp/node-b/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip join request node-b.catofes. "$$tmp/node-b.key.json" "$$tmp/node-b.request.json" >/dev/null; \
	PHOTON_CONFIG="$$tmp/catofes/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip delegate issue --direct "$$tmp/node-b.request.json" "$$tmp/node-b.bundle.json" >/dev/null; \
	PHOTON_CONFIG="$$tmp/node-b/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip join accept --direct "$$tmp/node-b.bundle.json" "$$tmp/node-b.key.json" >/dev/null; \
	PHOTON_CONFIG="$$tmp/node-b/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip record put --direct node-b.catofes. identity node-b >/dev/null; \
	PHOTON_CONFIG="$$tmp/node-b/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) debug verify node-b.catofes. >/dev/null; \
	echo "Join smoke passed"

zone-sort-smoke:
	$(GO_ENV) $(GO) test ./internal/inspect -run 'Test(SortZoneStringsGroupsDotAndHyphenSuffixes|BuildRecordsDebugGroupsZonesByDotAndHyphenSuffix)'
	$(GO_ENV) $(GO) test ./internal/inspect -run '^TestBuildSyncStatusGroupsZonesByDotAndHyphenSuffix$$'
	@echo "Zone sort smoke passed"

record-view-smoke:
	$(GO_ENV) $(GO) test ./internal/inspect/text -run 'TestWriteRecords(IsHumanReadableAndFilters|ShowsValuesByDefault|EscapesMultilineTableValues)|TestWriteRecordHidesDiagnosticFields'
	@echo "Record view smoke passed"

cli-surface-smoke:
	$(GO_ENV) $(GO) test ./app/photon -run 'Test(ShowFlagsWorkBeforeAndAfterSubcommand|HumanCommandsUsePlaneOrientedShowViews|DelegationCommandsOwnPermissionManagement|PrintRouteShowReportUsesFilteredVerboseTable|ServiceCLIExposesTableAndLocalViews)'
	$(GO_ENV) $(GO) test ./internal/inspect/text -run 'TestWrite(ZonesUsesSummaryAndVerboseTables|GossipPeersUsesGossipRuntimeFields|LinksUsesTransportSummaryAndVerboseTables|FirewallSummaryFiltersAndHidesDebugDetails|ServicesShowsPublishedAndLocalServices)'
	@echo "CLI surface smoke passed"

# phase1-smoke 流程：
# 1. 创建 root、catofes、node-a、node-b 四个隔离状态目录。
# 2. 建立 "." -> catofes. -> node-a/node-b 的完整 delegation chain。
# 3. join bundle 只携带各节点自己的最小 trust chain；对端状态通过同步获取。
# 4. 启动 node-b 的 sync serve，node-a 写入 identity 后执行一次 sync once。
# 5. sync once 允许 pending zones；最终只断言 B 已收到并可展示 A 的 record。
phase1-smoke: build
	@set -eu; \
	tmp="$${TMPDIR:-/tmp}/photon-phase1-smoke"; \
	rm -rf "$$tmp"; \
	mkdir -p "$$tmp/admin" "$$tmp/catofes" "$$tmp/a" "$$tmp/b"; \
	printf '%s\n' 'data_dir: '"$$tmp/admin" 'gossip:' '  peer_id: node-admin' '  listen_addr: 127.0.0.1:43433' > "$$tmp/admin/config.yaml"; \
	printf '%s\n' 'data_dir: '"$$tmp/catofes" 'gossip:' '  peer_id: zone-catofes-admin' '  listen_addr: 127.0.0.1:43436' > "$$tmp/catofes/config.yaml"; \
	printf '%s\n' 'data_dir: '"$$tmp/a" 'gossip:' '  peer_id: node-a.catofes.' '  listen_addr: 127.0.0.1:43434' '  bootstrap:' '    - id: node-b.catofes.' '      addr: 127.0.0.1:43435' > "$$tmp/a/config.yaml"; \
	printf '%s\n' 'data_dir: '"$$tmp/b" 'gossip:' '  peer_id: node-b.catofes.' '  listen_addr: 127.0.0.1:43435' '  bootstrap:' '    - id: node-a.catofes.' '      addr: 127.0.0.1:43434' > "$$tmp/b/config.yaml"; \
	PHOTON_CONFIG="$$tmp/admin/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip root init >/dev/null; \
	root_key="$$(PHOTON_CONFIG="$$tmp/admin/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip root pubkey)"; \
	printf '%s\n' 'trusted_root_public_key: '"$$root_key" >> "$$tmp/catofes/config.yaml"; \
	printf '%s\n' 'trusted_root_public_key: '"$$root_key" >> "$$tmp/a/config.yaml"; \
	printf '%s\n' 'trusted_root_public_key: '"$$root_key" >> "$$tmp/b/config.yaml"; \
	PHOTON_CONFIG="$$tmp/catofes/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip keygen "$$tmp/catofes.key.json" >/dev/null; \
	PHOTON_CONFIG="$$tmp/catofes/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip join request catofes. "$$tmp/catofes.key.json" "$$tmp/catofes.request.json" >/dev/null; \
	PHOTON_CONFIG="$$tmp/admin/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip delegate issue --direct "$$tmp/catofes.request.json" "$$tmp/catofes.bundle.json" >/dev/null; \
	PHOTON_CONFIG="$$tmp/catofes/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip join accept --direct "$$tmp/catofes.bundle.json" "$$tmp/catofes.key.json" >/dev/null; \
	PHOTON_CONFIG="$$tmp/a/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip keygen "$$tmp/node-a.key.json" >/dev/null; \
	PHOTON_CONFIG="$$tmp/a/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip join request node-a.catofes. "$$tmp/node-a.key.json" "$$tmp/node-a.request.json" >/dev/null; \
	PHOTON_CONFIG="$$tmp/catofes/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip delegate issue --direct "$$tmp/node-a.request.json" "$$tmp/node-a.bundle.json" >/dev/null; \
	PHOTON_CONFIG="$$tmp/b/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip keygen "$$tmp/node-b.key.json" >/dev/null; \
	PHOTON_CONFIG="$$tmp/b/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip join request node-b.catofes. "$$tmp/node-b.key.json" "$$tmp/node-b.request.json" >/dev/null; \
	PHOTON_CONFIG="$$tmp/catofes/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip delegate issue --direct "$$tmp/node-b.request.json" "$$tmp/node-b.bundle.json" >/dev/null; \
	PHOTON_CONFIG="$$tmp/a/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip join accept --direct "$$tmp/node-a.bundle.json" "$$tmp/node-a.key.json" >/dev/null; \
	PHOTON_CONFIG="$$tmp/b/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip join accept --direct "$$tmp/node-b.bundle.json" "$$tmp/node-b.key.json" >/dev/null; \
	PHOTON_CONFIG="$$tmp/b/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) advanced sync serve >"$$tmp/b.log" 2>&1 & \
	server_pid="$$!"; \
	trap 'status="$$?"; kill "$$server_pid" >/dev/null 2>&1 || true; if [ "$$status" != 0 ]; then cat "$$tmp/a.log" "$$tmp/b.log" 2>/dev/null || true; fi; exit "$$status"' EXIT; \
	sleep 1; \
	if ! kill -0 "$$server_pid" >/dev/null 2>&1; then cat "$$tmp/b.log"; exit 1; fi; \
	PHOTON_CONFIG="$$tmp/a/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip record put --direct node-a.catofes. identity node-a >/dev/null; \
	PHOTON_CONFIG="$$tmp/a/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) advanced sync once node-b.catofes. >"$$tmp/a.log" 2>&1 || grep -q 'pending zones' "$$tmp/a.log"; \
	kill "$$server_pid" >/dev/null 2>&1 || true; \
	wait "$$server_pid" >/dev/null 2>&1 || true; \
	PHOTON_CONFIG="$$tmp/b/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip record list node-a.catofes. --filter identity | grep -q 'identity'; \
	echo "Phase1 smoke passed"

# phase2-smoke 流程：
# 1. 创建 root、catofes、node-a、node-b，并写入相同 trusted_root_public_key。
# 2. A/B 用最小 join bundle 加入，后续对端 delegation/record 通过同步获得。
# 3. A/B 分别写入自己的 identity record。
# 4. 先启动 B serve 让 A 拉取 B，再启动 A serve 让 B 拉取 A。
# 5. 最后检查双方 record list、sync status 和 verify，证明双向收敛。
phase2-smoke: build
	@set -eu; \
	tmp="$${TMPDIR:-/tmp}/photon-phase2-smoke"; \
	rm -rf "$$tmp"; \
	mkdir -p "$$tmp/admin" "$$tmp/catofes" "$$tmp/a" "$$tmp/b"; \
	printf '%s\n' 'data_dir: '"$$tmp/admin" 'gossip:' '  peer_id: node-admin' '  listen_addr: 127.0.0.1:43443' > "$$tmp/admin/config.yaml"; \
	printf '%s\n' 'data_dir: '"$$tmp/catofes" 'gossip:' '  peer_id: zone-catofes-admin' '  listen_addr: 127.0.0.1:43446' > "$$tmp/catofes/config.yaml"; \
	printf '%s\n' 'data_dir: '"$$tmp/a" 'gossip:' '  peer_id: node-a.catofes.' '  listen_addr: 127.0.0.1:43444' '  bootstrap:' '    - id: node-b.catofes.' '      addr: 127.0.0.1:43445' > "$$tmp/a/config.yaml"; \
	printf '%s\n' 'data_dir: '"$$tmp/b" 'gossip:' '  peer_id: node-b.catofes.' '  listen_addr: 127.0.0.1:43445' '  bootstrap:' '    - id: node-a.catofes.' '      addr: 127.0.0.1:43444' > "$$tmp/b/config.yaml"; \
	PHOTON_CONFIG="$$tmp/admin/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip root init >/dev/null; \
	root_key="$$(PHOTON_CONFIG="$$tmp/admin/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip root pubkey)"; \
	printf '%s\n' 'trusted_root_public_key: '"$$root_key" >> "$$tmp/catofes/config.yaml"; \
	printf '%s\n' 'trusted_root_public_key: '"$$root_key" >> "$$tmp/a/config.yaml"; \
	printf '%s\n' 'trusted_root_public_key: '"$$root_key" >> "$$tmp/b/config.yaml"; \
	PHOTON_CONFIG="$$tmp/catofes/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip keygen "$$tmp/catofes.key.json" >/dev/null; \
	PHOTON_CONFIG="$$tmp/catofes/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip join request catofes. "$$tmp/catofes.key.json" "$$tmp/catofes.request.json" >/dev/null; \
	PHOTON_CONFIG="$$tmp/admin/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip delegate issue --direct "$$tmp/catofes.request.json" "$$tmp/catofes.bundle.json" >/dev/null; \
	PHOTON_CONFIG="$$tmp/catofes/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip join accept --direct "$$tmp/catofes.bundle.json" "$$tmp/catofes.key.json" >/dev/null; \
	PHOTON_CONFIG="$$tmp/a/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip keygen "$$tmp/node-a.key.json" >/dev/null; \
	PHOTON_CONFIG="$$tmp/a/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip join request node-a.catofes. "$$tmp/node-a.key.json" "$$tmp/node-a.request.json" >/dev/null; \
	PHOTON_CONFIG="$$tmp/catofes/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip delegate issue --direct "$$tmp/node-a.request.json" "$$tmp/node-a.bundle.json" >/dev/null; \
	PHOTON_CONFIG="$$tmp/b/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip keygen "$$tmp/node-b.key.json" >/dev/null; \
	PHOTON_CONFIG="$$tmp/b/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip join request node-b.catofes. "$$tmp/node-b.key.json" "$$tmp/node-b.request.json" >/dev/null; \
	PHOTON_CONFIG="$$tmp/catofes/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip delegate issue --direct "$$tmp/node-b.request.json" "$$tmp/node-b.bundle.json" >/dev/null; \
	PHOTON_CONFIG="$$tmp/a/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip join accept --direct "$$tmp/node-a.bundle.json" "$$tmp/node-a.key.json" >/dev/null; \
	PHOTON_CONFIG="$$tmp/b/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip join accept --direct "$$tmp/node-b.bundle.json" "$$tmp/node-b.key.json" >/dev/null; \
	PHOTON_CONFIG="$$tmp/a/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip record put --direct node-a.catofes. identity node-a >/dev/null; \
	PHOTON_CONFIG="$$tmp/b/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip record put --direct node-b.catofes. identity node-b >/dev/null; \
	PHOTON_CONFIG="$$tmp/b/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) advanced sync serve >"$$tmp/b.log" 2>&1 & server_pid="$$!"; \
	trap 'status="$$?"; kill "$$server_pid" >/dev/null 2>&1 || true; if [ "$$status" != 0 ]; then cat "$$tmp/a.log" "$$tmp/b.log" 2>/dev/null || true; fi; exit "$$status"' EXIT; \
	sleep 1; \
	PHOTON_CONFIG="$$tmp/a/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) advanced sync once node-b.catofes. >"$$tmp/a.log" 2>&1 || grep -q 'pending zones' "$$tmp/a.log"; \
	sleep 1; \
	kill "$$server_pid" >/dev/null 2>&1 || true; \
	wait "$$server_pid" >/dev/null 2>&1 || true; \
	PHOTON_CONFIG="$$tmp/a/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) advanced sync serve >"$$tmp/a.log" 2>&1 & server_pid="$$!"; \
	sleep 1; \
	PHOTON_CONFIG="$$tmp/b/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) advanced sync once node-a.catofes. >"$$tmp/b.log" 2>&1 || grep -q 'pending zones' "$$tmp/b.log"; \
	sleep 1; \
	kill "$$server_pid" >/dev/null 2>&1 || true; \
	wait "$$server_pid" >/dev/null 2>&1 || true; \
	PHOTON_CONFIG="$$tmp/a/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip record list node-b.catofes. --filter identity | grep -q 'identity'; \
	PHOTON_CONFIG="$$tmp/b/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip record list node-a.catofes. --filter identity | grep -q 'identity'; \
	PHOTON_CONFIG="$$tmp/a/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) advanced sync status | grep -q 'peer node-b.catofes.'; \
	PHOTON_CONFIG="$$tmp/b/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) advanced sync status | grep -q 'peer node-a.catofes.'; \
	PHOTON_CONFIG="$$tmp/a/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) debug verify node-a.catofes. >/dev/null; \
	PHOTON_CONFIG="$$tmp/a/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) debug verify node-b.catofes. >/dev/null; \
	PHOTON_CONFIG="$$tmp/b/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) debug verify node-a.catofes. >/dev/null; \
	PHOTON_CONFIG="$$tmp/b/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) debug verify node-b.catofes. >/dev/null; \
	echo "Phase2 two-node smoke passed"

# phase2-run-smoke 流程：
# 1. 准备两节点 delegation chain，并让 A 先写入 identity。
# 2. 启动 A 的 daemon，再延迟启动 B，验证 B 可自动追上 A。
# 3. 停止 B，模拟 peer 离线。
# 4. B 离线修改本地 record 后重新启动 daemon。
# 5. 断言 A 自动收到 B 的新 record，A/B verified state 的 root 一致。
phase2-run-smoke: build
	@set -eu; \
	tmp="$${TMPDIR:-/tmp}/photon-phase2-run-smoke"; \
	rm -rf "$$tmp"; \
	mkdir -p "$$tmp/admin" "$$tmp/catofes" "$$tmp/a" "$$tmp/b"; \
	printf '%s\n' 'data_dir: '"$$tmp/admin" 'gossip:' '  peer_id: node-admin' '  listen_addr: 127.0.0.1:43463' > "$$tmp/admin/config.yaml"; \
	printf '%s\n' 'data_dir: '"$$tmp/catofes" 'gossip:' '  peer_id: zone-catofes-admin' '  listen_addr: 127.0.0.1:43466' > "$$tmp/catofes/config.yaml"; \
	printf '%s\n' 'data_dir: '"$$tmp/a" 'gossip:' '  peer_id: node-a.catofes.' '  listen_addr: 127.0.0.1:43464' '  advertise_addr: 127.0.0.1:43464' '  publish_endpoints: false' '  bootstrap:' '    - id: node-b.catofes.' '      addr: 127.0.0.1:43465' > "$$tmp/a/config.yaml"; \
	printf '%s\n' 'data_dir: '"$$tmp/b" 'gossip:' '  peer_id: node-b.catofes.' '  listen_addr: 127.0.0.1:43465' '  advertise_addr: 127.0.0.1:43465' '  publish_endpoints: false' '  bootstrap:' '    - id: node-a.catofes.' '      addr: 127.0.0.1:43464' > "$$tmp/b/config.yaml"; \
	PHOTON_CONFIG="$$tmp/admin/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip root init >/dev/null; \
	root_key="$$(PHOTON_CONFIG="$$tmp/admin/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip root pubkey)"; \
	printf '%s\n' 'trusted_root_public_key: '"$$root_key" >> "$$tmp/catofes/config.yaml"; \
	printf '%s\n' 'trusted_root_public_key: '"$$root_key" >> "$$tmp/a/config.yaml"; \
	printf '%s\n' 'trusted_root_public_key: '"$$root_key" >> "$$tmp/b/config.yaml"; \
	PHOTON_CONFIG="$$tmp/catofes/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip keygen "$$tmp/catofes.key.json" >/dev/null; \
	PHOTON_CONFIG="$$tmp/catofes/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip join request catofes. "$$tmp/catofes.key.json" "$$tmp/catofes.request.json" >/dev/null; \
	PHOTON_CONFIG="$$tmp/admin/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip delegate issue --direct "$$tmp/catofes.request.json" "$$tmp/catofes.bundle.json" >/dev/null; \
	PHOTON_CONFIG="$$tmp/catofes/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip join accept --direct "$$tmp/catofes.bundle.json" "$$tmp/catofes.key.json" >/dev/null; \
	PHOTON_CONFIG="$$tmp/a/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip keygen "$$tmp/node-a.key.json" >/dev/null; \
	PHOTON_CONFIG="$$tmp/a/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip join request node-a.catofes. "$$tmp/node-a.key.json" "$$tmp/node-a.request.json" >/dev/null; \
	PHOTON_CONFIG="$$tmp/catofes/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip delegate issue --direct "$$tmp/node-a.request.json" "$$tmp/node-a.bundle.json" >/dev/null; \
	PHOTON_CONFIG="$$tmp/a/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip join accept --direct "$$tmp/node-a.bundle.json" "$$tmp/node-a.key.json" >/dev/null; \
	PHOTON_CONFIG="$$tmp/b/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip keygen "$$tmp/node-b.key.json" >/dev/null; \
	PHOTON_CONFIG="$$tmp/b/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip join request node-b.catofes. "$$tmp/node-b.key.json" "$$tmp/node-b.request.json" >/dev/null; \
	PHOTON_CONFIG="$$tmp/catofes/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip delegate issue --direct "$$tmp/node-b.request.json" "$$tmp/node-b.bundle.json" >/dev/null; \
	PHOTON_CONFIG="$$tmp/b/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip join accept --direct "$$tmp/node-b.bundle.json" "$$tmp/node-b.key.json" >/dev/null; \
	PHOTON_CONFIG="$$tmp/a/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip record put --direct node-a.catofes. identity node-a >/dev/null; \
	PHOTON_CONFIG="$$tmp/a/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) daemon --interval 1 >"$$tmp/a.log" 2>&1 & a_pid="$$!"; \
	b_pid=""; \
	trap 'status="$$?"; kill "$$a_pid" "$$b_pid" >/dev/null 2>&1 || true; if [ "$$status" != 0 ]; then cat "$$tmp/a.log" "$$tmp/b.log" "$$tmp/b-restart.log" 2>/dev/null || true; fi; exit "$$status"' EXIT; \
	sleep 2; \
	PHOTON_CONFIG="$$tmp/b/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) daemon --interval 1 >"$$tmp/b.log" 2>&1 & b_pid="$$!"; \
	for i in 1 2 3 4 5; do if [ -S "$$tmp/b/photon.sock" ]; then break; fi; sleep 1; done; \
	[ -S "$$tmp/b/photon.sock" ]; \
	for i in 1 2 3 4 5; do if PHOTON_CONFIG="$$tmp/b/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip record list node-a.catofes. --filter identity | grep -q 'identity'; then break; fi; sleep 1; done; \
	PHOTON_CONFIG="$$tmp/b/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip record list node-a.catofes. --filter identity | grep -q 'identity'; \
	kill "$$b_pid" >/dev/null 2>&1 || true; wait "$$b_pid" >/dev/null 2>&1 || true; b_pid=""; \
	PHOTON_CONFIG="$$tmp/b/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip record put --direct node-b.catofes. identity node-b-restored >/dev/null; \
	PHOTON_CONFIG="$$tmp/b/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) daemon --interval 1 >"$$tmp/b-restart.log" 2>&1 & b_pid="$$!"; \
	for i in 1 2 3 4 5; do if PHOTON_CONFIG="$$tmp/a/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip record list node-b.catofes. --filter identity --verbose | grep -q 'node-b-restored'; then break; fi; sleep 1; done; \
	PHOTON_CONFIG="$$tmp/a/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip record list node-b.catofes. --filter identity --verbose | grep -q 'node-b-restored'; \
	PHOTON_CONFIG="$$tmp/a/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) debug verify node-b.catofes. >/dev/null; \
	a_root="$$(PHOTON_CONFIG="$$tmp/a/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) advanced sync status | awk '/^local_root:/ {print $$2}')"; \
	b_root="$$(PHOTON_CONFIG="$$tmp/b/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) advanced sync status | awk '/^local_root:/ {print $$2}')"; \
	[ "$$a_root" = "$$b_root" ]; \
	kill "$$a_pid" "$$b_pid" >/dev/null 2>&1 || true; \
	echo "Phase2 daemon smoke passed"

# phase3-daemon-smoke 流程：
# 1. 准备 A/B 两节点和可发布的本地 advertise_addr。
# 2. 分别启动 B 和 A 的 daemon，等待 control socket 就绪。
# 3. 通过 A 的 control socket 执行 record put，确认输出显示 via daemon。
# 4. 等待 B 通过 gossip 收到 A 的 record。
# 5. 在 B 上 verify A，证明 daemon 写入和同步路径都有效。
phase3-daemon-smoke: build
	@set -eu; \
	tmp="$${TMPDIR:-/tmp}/photon-phase3-daemon-smoke"; \
	rm -rf "$$tmp"; \
	mkdir -p "$$tmp/admin" "$$tmp/catofes" "$$tmp/a" "$$tmp/b"; \
	printf '%s\n' 'data_dir: '"$$tmp/admin" 'gossip:' '  peer_id: node-admin' '  listen_addr: 127.0.0.1:43520' > "$$tmp/admin/config.yaml"; \
	printf '%s\n' 'data_dir: '"$$tmp/catofes" 'gossip:' '  peer_id: zone-catofes-admin' '  listen_addr: 127.0.0.1:43521' > "$$tmp/catofes/config.yaml"; \
	printf '%s\n' 'data_dir: '"$$tmp/a" 'gossip:' '  peer_id: node-a.catofes.' '  listen_addr: 127.0.0.1:43522' '  advertise_addr: 127.0.0.1:43522' '  bootstrap:' '    - id: node-b.catofes.' '      addr: 127.0.0.1:43523' > "$$tmp/a/config.yaml"; \
	printf '%s\n' 'data_dir: '"$$tmp/b" 'gossip:' '  peer_id: node-b.catofes.' '  listen_addr: 127.0.0.1:43523' '  advertise_addr: 127.0.0.1:43523' '  bootstrap:' '    - id: node-a.catofes.' '      addr: 127.0.0.1:43522' > "$$tmp/b/config.yaml"; \
	PHOTON_CONFIG="$$tmp/admin/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip root init >/dev/null; \
	root_key="$$(PHOTON_CONFIG="$$tmp/admin/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip root pubkey)"; \
	for node in catofes a b; do printf '%s\n' 'trusted_root_public_key: '"$$root_key" >> "$$tmp/$$node/config.yaml"; done; \
	PHOTON_CONFIG="$$tmp/catofes/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip keygen "$$tmp/catofes.key.json" >/dev/null; \
	PHOTON_CONFIG="$$tmp/catofes/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip join request catofes. "$$tmp/catofes.key.json" "$$tmp/catofes.request.json" >/dev/null; \
	PHOTON_CONFIG="$$tmp/admin/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip delegate issue --direct "$$tmp/catofes.request.json" "$$tmp/catofes.bundle.json" >/dev/null; \
	PHOTON_CONFIG="$$tmp/catofes/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip join accept --direct "$$tmp/catofes.bundle.json" "$$tmp/catofes.key.json" >/dev/null; \
	for node in a b; do PHOTON_CONFIG="$$tmp/$$node/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip keygen "$$tmp/node-$$node.key.json" >/dev/null; PHOTON_CONFIG="$$tmp/$$node/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip join request node-$$node.catofes. "$$tmp/node-$$node.key.json" "$$tmp/node-$$node.request.json" >/dev/null; PHOTON_CONFIG="$$tmp/catofes/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip delegate issue --direct "$$tmp/node-$$node.request.json" "$$tmp/node-$$node.bundle.json" >/dev/null; PHOTON_CONFIG="$$tmp/$$node/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip join accept --direct "$$tmp/node-$$node.bundle.json" "$$tmp/node-$$node.key.json" >/dev/null; done; \
	PHOTON_CONTROL_SOCKET="$$tmp/b/photon.sock" PHOTON_CONFIG="$$tmp/b/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) daemon --interval 60 >"$$tmp/b.log" 2>&1 & b_pid="$$!"; \
	sleep 4; \
	PHOTON_CONTROL_SOCKET="$$tmp/a/photon.sock" PHOTON_CONFIG="$$tmp/a/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) daemon --interval 60 >"$$tmp/a.log" 2>&1 & a_pid="$$!"; \
	trap 'status="$$?"; kill "$$a_pid" "$$b_pid" >/dev/null 2>&1 || true; if [ "$$status" != 0 ]; then cat "$$tmp/a.log" "$$tmp/b.log" "$$tmp/record-put.out" 2>/dev/null || true; fi; exit "$$status"' EXIT; \
	for i in 1 2 3 4 5; do if [ -S "$$tmp/a/photon.sock" ] && [ -S "$$tmp/b/photon.sock" ]; then break; fi; sleep 1; done; \
	[ -S "$$tmp/a/photon.sock" ]; \
	[ -S "$$tmp/b/photon.sock" ]; \
	for i in 1 2 3 4 5; do if PHOTON_CONTROL_SOCKET="$$tmp/a/photon.sock" PHOTON_CONFIG="$$tmp/a/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) advanced sync status --verbose 2>/dev/null | grep -q 'daemon: online'; then break; fi; sleep 1; done; \
	PHOTON_CONTROL_SOCKET="$$tmp/a/photon.sock" PHOTON_CONFIG="$$tmp/a/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) advanced sync status --verbose | grep -q 'daemon: online'; \
	PHOTON_CONTROL_SOCKET="$$tmp/a/photon.sock" PHOTON_CONFIG="$$tmp/a/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip record put node-a.catofes. identity node-a-daemon >"$$tmp/record-put.out"; \
	grep -q 'via daemon' "$$tmp/record-put.out"; \
	for i in 1 2 3 4 5 6 7 8; do if PHOTON_CONFIG="$$tmp/b/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip record list node-a.catofes. --filter identity 2>/dev/null | grep -q 'identity'; then break; fi; sleep 1; done; \
	PHOTON_CONFIG="$$tmp/b/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip record list node-a.catofes. --filter identity 2>/dev/null | grep -q 'identity'; \
	PHOTON_CONFIG="$$tmp/b/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) debug verify node-a.catofes. >/dev/null; \
	kill "$$a_pid" "$$b_pid" >/dev/null 2>&1 || true; \
	echo "Phase3 daemon smoke passed"

# phase3-daemon-fallback-smoke 流程：
# 1. 准备 A/B 两节点和 advertise_addr。
# 2. 让 A 的 record put 指向不存在的 control socket，验证 fail closed；随后显式 --direct 写 state。
# 3. 启动 B/A daemon，并确认 control socket 与 daemon 状态可用。
# 4. 等待 B 收到 A 在 daemon 启动前写入的 record。
# 5. verify A，确保显式 direct 写入不会在 daemon 接管后丢失。
phase3-daemon-fallback-smoke: build
	@set -eu; \
	tmp="$${TMPDIR:-/tmp}/photon-phase3-daemon-fallback-smoke"; \
	rm -rf "$$tmp"; \
	mkdir -p "$$tmp/admin" "$$tmp/catofes" "$$tmp/a" "$$tmp/b"; \
	printf '%s\n' 'data_dir: '"$$tmp/admin" 'gossip:' '  peer_id: node-admin' '  listen_addr: 127.0.0.1:43530' > "$$tmp/admin/config.yaml"; \
	printf '%s\n' 'data_dir: '"$$tmp/catofes" 'gossip:' '  peer_id: zone-catofes-admin' '  listen_addr: 127.0.0.1:43531' > "$$tmp/catofes/config.yaml"; \
	printf '%s\n' 'data_dir: '"$$tmp/a" 'gossip:' '  peer_id: node-a.catofes.' '  listen_addr: 127.0.0.1:43532' '  advertise_addr: 127.0.0.1:43532' '  bootstrap:' '    - id: node-b.catofes.' '      addr: 127.0.0.1:43533' > "$$tmp/a/config.yaml"; \
	printf '%s\n' 'data_dir: '"$$tmp/b" 'gossip:' '  peer_id: node-b.catofes.' '  listen_addr: 127.0.0.1:43533' '  advertise_addr: 127.0.0.1:43533' '  bootstrap:' '    - id: node-a.catofes.' '      addr: 127.0.0.1:43532' > "$$tmp/b/config.yaml"; \
	PHOTON_CONFIG="$$tmp/admin/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip root init >/dev/null; \
	root_key="$$(PHOTON_CONFIG="$$tmp/admin/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip root pubkey)"; \
	for node in catofes a b; do printf '%s\n' 'trusted_root_public_key: '"$$root_key" >> "$$tmp/$$node/config.yaml"; done; \
	PHOTON_CONFIG="$$tmp/catofes/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip keygen "$$tmp/catofes.key.json" >/dev/null; \
	PHOTON_CONFIG="$$tmp/catofes/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip join request catofes. "$$tmp/catofes.key.json" "$$tmp/catofes.request.json" >/dev/null; \
	PHOTON_CONFIG="$$tmp/admin/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip delegate issue --direct "$$tmp/catofes.request.json" "$$tmp/catofes.bundle.json" >/dev/null; \
	PHOTON_CONFIG="$$tmp/catofes/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip join accept --direct "$$tmp/catofes.bundle.json" "$$tmp/catofes.key.json" >/dev/null; \
	for node in a b; do PHOTON_CONFIG="$$tmp/$$node/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip keygen "$$tmp/node-$$node.key.json" >/dev/null; PHOTON_CONFIG="$$tmp/$$node/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip join request node-$$node.catofes. "$$tmp/node-$$node.key.json" "$$tmp/node-$$node.request.json" >/dev/null; PHOTON_CONFIG="$$tmp/catofes/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip delegate issue --direct "$$tmp/node-$$node.request.json" "$$tmp/node-$$node.bundle.json" >/dev/null; PHOTON_CONFIG="$$tmp/$$node/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip join accept --direct "$$tmp/node-$$node.bundle.json" "$$tmp/node-$$node.key.json" >/dev/null; done; \
	if PHOTON_CONTROL_SOCKET="$$tmp/a/missing.sock" PHOTON_CONFIG="$$tmp/a/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip record put node-a.catofes. identity node-a-rejected 2>"$$tmp/fallback.err" >/dev/null; then exit 1; fi; \
	grep -q 'daemon control socket unavailable' "$$tmp/fallback.err"; \
	if PHOTON_CONFIG="$$tmp/a/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip record get node-a.catofes. identity >/dev/null 2>&1; then exit 1; fi; \
	PHOTON_CONFIG="$$tmp/a/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip record put --direct node-a.catofes. identity node-a-direct >/dev/null; \
	PHOTON_CONTROL_SOCKET="$$tmp/b/photon.sock" PHOTON_CONFIG="$$tmp/b/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) daemon --interval 60 >"$$tmp/b.log" 2>&1 & b_pid="$$!"; \
	sleep 4; \
	PHOTON_CONTROL_SOCKET="$$tmp/a/photon.sock" PHOTON_CONFIG="$$tmp/a/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) daemon --interval 60 >"$$tmp/a.log" 2>&1 & a_pid="$$!"; \
	trap 'status="$$?"; kill "$$a_pid" "$$b_pid" >/dev/null 2>&1 || true; if [ "$$status" != 0 ]; then cat "$$tmp/a.log" "$$tmp/b.log" "$$tmp/fallback.err" 2>/dev/null || true; fi; exit "$$status"' EXIT; \
	for i in 1 2 3 4 5; do if [ -S "$$tmp/a/photon.sock" ] && [ -S "$$tmp/b/photon.sock" ]; then break; fi; sleep 1; done; \
	[ -S "$$tmp/a/photon.sock" ]; \
	[ -S "$$tmp/b/photon.sock" ]; \
	PHOTON_CONTROL_SOCKET="$$tmp/a/photon.sock" PHOTON_CONFIG="$$tmp/a/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) advanced sync status --verbose | grep -q 'daemon: online'; \
	for i in 1 2 3 4 5 6 7 8; do if PHOTON_CONFIG="$$tmp/b/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip record list node-a.catofes. --filter identity 2>/dev/null | grep -q 'identity'; then break; fi; sleep 1; done; \
	PHOTON_CONFIG="$$tmp/b/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip record list node-a.catofes. --filter identity 2>/dev/null | grep -q 'identity'; \
	PHOTON_CONFIG="$$tmp/b/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) debug verify node-a.catofes. >/dev/null; \
	kill "$$a_pid" "$$b_pid" >/dev/null 2>&1 || true; \
	echo "Phase3 daemon fail-closed smoke passed"

# admin-daemon-smoke 流程：
# 1. root admin 离线初始化 "."，随后启动 root admin daemon。
# 2. catofes. 生成 join request，并通过 root admin control socket 签发 bundle。
# 3. root admin 通过 control socket 为 catofes. 追加 allocate-ip，catofes.
#    接受 refresh bundle 后启动自己的 daemon。
# 4. node-b 生成 join request，并通过 catofes. control socket 签发 leaf bundle。
# 5. 通过 catofes. control socket 撤销 node-b，验证 revocation 持久化且 direct delegation 被清理。
admin-daemon-smoke: build
	@set -eu; \
	tmp="$${TMPDIR:-/tmp}/photon-admin-daemon-smoke"; \
	rm -rf "$$tmp"; \
	mkdir -p "$$tmp/admin" "$$tmp/catofes" "$$tmp/node-b"; \
	printf '%s\n' 'data_dir: '"$$tmp/admin" 'gossip:' '  peer_id: node-admin' '  listen_addr: 127.0.0.1:43540' > "$$tmp/admin/config.yaml"; \
	printf '%s\n' 'data_dir: '"$$tmp/catofes" 'gossip:' '  peer_id: zone-catofes-admin' '  listen_addr: 127.0.0.1:43541' > "$$tmp/catofes/config.yaml"; \
	printf '%s\n' 'data_dir: '"$$tmp/node-b" 'gossip:' '  peer_id: node-b.catofes.' '  listen_addr: 127.0.0.1:43542' > "$$tmp/node-b/config.yaml"; \
	PHOTON_CONFIG="$$tmp/admin/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip root init >/dev/null; \
	root_key="$$(PHOTON_CONFIG="$$tmp/admin/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip root pubkey)"; \
	for node in catofes node-b; do printf '%s\n' 'trusted_root_public_key: '"$$root_key" >> "$$tmp/$$node/config.yaml"; done; \
	PHOTON_CONTROL_SOCKET="$$tmp/admin/photon.sock" PHOTON_CONFIG="$$tmp/admin/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) daemon --interval 60 >"$$tmp/admin.log" 2>&1 & admin_pid="$$!"; \
	trap 'status="$$?"; kill "$$admin_pid" "$${catofes_pid:-}" >/dev/null 2>&1 || true; if [ "$$status" != 0 ]; then cat "$$tmp/admin.log" "$$tmp/catofes.log" "$$tmp/catofes-issue.out" "$$tmp/catofes-grant.out" "$$tmp/node-b-issue.out" "$$tmp/revoke.out" 2>/dev/null || true; fi; exit "$$status"' EXIT; \
	for i in 1 2 3 4 5; do if [ -S "$$tmp/admin/photon.sock" ]; then break; fi; sleep 1; done; \
	[ -S "$$tmp/admin/photon.sock" ]; \
	PHOTON_CONFIG="$$tmp/catofes/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip keygen "$$tmp/catofes.key.json" >/dev/null; \
	PHOTON_CONFIG="$$tmp/catofes/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip join request catofes. "$$tmp/catofes.key.json" "$$tmp/catofes.request.json" >/dev/null; \
	PHOTON_CONTROL_SOCKET="$$tmp/admin/photon.sock" PHOTON_CONFIG="$$tmp/admin/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip delegate issue "$$tmp/catofes.request.json" "$$tmp/catofes.bundle.json" >"$$tmp/catofes-issue.out"; \
	grep -q 'via daemon' "$$tmp/catofes-issue.out"; \
	PHOTON_CONFIG="$$tmp/catofes/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip join accept --direct "$$tmp/catofes.bundle.json" "$$tmp/catofes.key.json" >/dev/null; \
	PHOTON_CONTROL_SOCKET="$$tmp/admin/photon.sock" PHOTON_CONFIG="$$tmp/admin/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip delegate grant catofes. allocate-ip "$$tmp/catofes.grant.json" >"$$tmp/catofes-grant.out"; \
	grep -q 'via daemon' "$$tmp/catofes-grant.out"; \
	PHOTON_CONFIG="$$tmp/catofes/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip join accept --direct "$$tmp/catofes.grant.json" >/dev/null; \
	PHOTON_CONFIG="$$tmp/catofes/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip zone show catofes. | grep -q 'allocate-ip'; \
	PHOTON_CONTROL_SOCKET="$$tmp/catofes/photon.sock" PHOTON_CONFIG="$$tmp/catofes/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) daemon --interval 60 >"$$tmp/catofes.log" 2>&1 & catofes_pid="$$!"; \
	for i in 1 2 3 4 5; do if [ -S "$$tmp/catofes/photon.sock" ]; then break; fi; sleep 1; done; \
	[ -S "$$tmp/catofes/photon.sock" ]; \
	PHOTON_CONFIG="$$tmp/node-b/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip keygen "$$tmp/node-b.key.json" >/dev/null; \
	PHOTON_CONFIG="$$tmp/node-b/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip join request node-b.catofes. "$$tmp/node-b.key.json" "$$tmp/node-b.request.json" >/dev/null; \
	PHOTON_CONTROL_SOCKET="$$tmp/catofes/photon.sock" PHOTON_CONFIG="$$tmp/catofes/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip delegate issue "$$tmp/node-b.request.json" "$$tmp/node-b.bundle.json" >"$$tmp/node-b-issue.out"; \
	grep -q 'via daemon' "$$tmp/node-b-issue.out"; \
	PHOTON_CONFIG="$$tmp/node-b/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip join accept --direct "$$tmp/node-b.bundle.json" "$$tmp/node-b.key.json" >/dev/null; \
	PHOTON_CONFIG="$$tmp/node-b/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) debug verify node-b.catofes. >/dev/null; \
	PHOTON_CONTROL_SOCKET="$$tmp/catofes/photon.sock" PHOTON_CONFIG="$$tmp/catofes/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip delegate revoke node-b.catofes. admin-daemon-smoke >"$$tmp/revoke.out"; \
	grep -q 'via daemon' "$$tmp/revoke.out"; \
	PHOTON_CONFIG="$$tmp/catofes/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) debug zone node-b.catofes. | grep -q 'revoked'; \
	if PHOTON_CONFIG="$$tmp/catofes/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) debug verify node-b.catofes. >/dev/null 2>&1; then exit 1; fi; \
	kill "$$admin_pid" "$$catofes_pid" >/dev/null 2>&1 || true; \
	echo "Admin daemon smoke passed"

# multi-node-smoke 流程：
# 1. 准备 A/B/C 三节点，A 作为 hub，B/C 只通过 A 同步。
# 2. 所有 leaf 用最小 join bundle 加入；hub 从同步 snapshot 学到其他 leaf。
# 3. B 写入 identity，A serve 后 B 先把状态推给 A。
# 4. C 对 A 执行 sync once，通过 A 学到 B 的 record。
# 5. 停止并重启 A 的 serve 路径，B 写入更高版本 record。
# 6. 断言 A 和 C 都看到 B 的新版本，验证重启恢复和 latest-record 收敛。
multi-node-smoke: build
	@set -eu; \
	tmp="$${TMPDIR:-/tmp}/photon-multi-node-smoke"; \
	rm -rf "$$tmp"; \
	mkdir -p "$$tmp/admin" "$$tmp/catofes" "$$tmp/a" "$$tmp/b" "$$tmp/c"; \
	printf '%s\n' 'data_dir: '"$$tmp/admin" 'gossip:' '  peer_id: node-admin' '  listen_addr: 127.0.0.1:43453' > "$$tmp/admin/config.yaml"; \
	printf '%s\n' 'data_dir: '"$$tmp/catofes" 'gossip:' '  peer_id: zone-catofes-admin' '  listen_addr: 127.0.0.1:43456' > "$$tmp/catofes/config.yaml"; \
	printf '%s\n' 'data_dir: '"$$tmp/a" 'gossip:' '  peer_id: node-a.catofes.' '  listen_addr: 127.0.0.1:43454' '  bootstrap:' '    - id: node-b.catofes.' '      addr: 127.0.0.1:43455' '    - id: node-c.catofes.' '      addr: 127.0.0.1:43457' > "$$tmp/a/config.yaml"; \
	printf '%s\n' 'data_dir: '"$$tmp/b" 'gossip:' '  peer_id: node-b.catofes.' '  listen_addr: 127.0.0.1:43455' '  bootstrap:' '    - id: node-a.catofes.' '      addr: 127.0.0.1:43454' > "$$tmp/b/config.yaml"; \
	printf '%s\n' 'data_dir: '"$$tmp/c" 'gossip:' '  peer_id: node-c.catofes.' '  listen_addr: 127.0.0.1:43457' '  bootstrap:' '    - id: node-a.catofes.' '      addr: 127.0.0.1:43454' > "$$tmp/c/config.yaml"; \
	PHOTON_CONFIG="$$tmp/admin/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip root init >/dev/null; \
	root_key="$$(PHOTON_CONFIG="$$tmp/admin/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip root pubkey)"; \
	for node in catofes a b c; do printf '%s\n' 'trusted_root_public_key: '"$$root_key" >> "$$tmp/$$node/config.yaml"; done; \
	PHOTON_CONFIG="$$tmp/catofes/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip keygen "$$tmp/catofes.key.json" >/dev/null; \
	PHOTON_CONFIG="$$tmp/catofes/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip join request catofes. "$$tmp/catofes.key.json" "$$tmp/catofes.request.json" >/dev/null; \
	PHOTON_CONFIG="$$tmp/admin/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip delegate issue --direct "$$tmp/catofes.request.json" "$$tmp/catofes.bundle.json" >/dev/null; \
	PHOTON_CONFIG="$$tmp/catofes/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip join accept --direct "$$tmp/catofes.bundle.json" "$$tmp/catofes.key.json" >/dev/null; \
	for node in a b c; do PHOTON_CONFIG="$$tmp/$$node/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip keygen "$$tmp/node-$$node.key.json" >/dev/null; PHOTON_CONFIG="$$tmp/$$node/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip join request node-$$node.catofes. "$$tmp/node-$$node.key.json" "$$tmp/node-$$node.request.json" >/dev/null; done; \
	for node in a b c; do PHOTON_CONFIG="$$tmp/catofes/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip delegate issue --direct "$$tmp/node-$$node.request.json" "$$tmp/node-$$node.bundle.json" >/dev/null; done; \
	for node in a b c; do PHOTON_CONFIG="$$tmp/$$node/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip join accept --direct "$$tmp/node-$$node.bundle.json" "$$tmp/node-$$node.key.json" >/dev/null; done; \
	PHOTON_CONFIG="$$tmp/b/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip record put --direct node-b.catofes. identity node-b >/dev/null; \
	PHOTON_CONFIG="$$tmp/a/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) advanced sync serve >"$$tmp/a.log" 2>&1 & server_pid="$$!"; \
	trap 'status="$$?"; kill "$$server_pid" >/dev/null 2>&1 || true; if [ "$$status" != 0 ]; then cat "$$tmp/a.log" "$$tmp/a-restart.log" 2>/dev/null || true; fi; exit "$$status"' EXIT; \
	sleep 1; \
	PHOTON_CONFIG="$$tmp/b/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) advanced sync once node-a.catofes. >"$$tmp/b-to-a.log" 2>&1 || grep -q 'pending zones' "$$tmp/b-to-a.log"; \
	sleep 1; \
	PHOTON_CONFIG="$$tmp/c/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) advanced sync once node-a.catofes. >"$$tmp/c-to-a.log" 2>&1 || grep -q 'pending zones' "$$tmp/c-to-a.log"; \
	sleep 1; \
	PHOTON_CONFIG="$$tmp/c/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) advanced sync once node-a.catofes. >"$$tmp/c-to-a-2.log" 2>&1 || grep -q 'pending zones' "$$tmp/c-to-a-2.log"; \
	sleep 1; \
	kill "$$server_pid" >/dev/null 2>&1 || true; \
	wait "$$server_pid" >/dev/null 2>&1 || true; \
	PHOTON_CONFIG="$$tmp/c/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip record list node-b.catofes. --filter identity | grep -q 'identity'; \
	PHOTON_CONFIG="$$tmp/c/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) debug verify node-b.catofes. >/dev/null; \
	PHOTON_CONFIG="$$tmp/c/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) advanced sync status | grep -q 'peer node-a.catofes.'; \
	PHOTON_CONFIG="$$tmp/b/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip record put --direct node-b.catofes. identity node-b-restarted >/dev/null; \
	PHOTON_CONFIG="$$tmp/a/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) advanced sync serve >"$$tmp/a-restart.log" 2>&1 & server_pid="$$!"; \
	sleep 1; \
	PHOTON_CONFIG="$$tmp/b/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) advanced sync once node-a.catofes. >"$$tmp/b-to-a-restart.log" 2>&1 || grep -q 'pending zones' "$$tmp/b-to-a-restart.log"; \
	sleep 1; \
	for i in 1 2 3 4 5 6 7 8; do \
		PHOTON_CONFIG="$$tmp/c/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) advanced sync once node-a.catofes. >"$$tmp/c-to-a-restart-$$i.log" 2>&1 || grep -q 'pending zones' "$$tmp/c-to-a-restart-$$i.log"; \
		if PHOTON_CONFIG="$$tmp/c/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip record list node-b.catofes. --filter identity --verbose 2>/dev/null | grep -q 'node-b-restarted'; then break; fi; \
		sleep 1; \
	done; \
	kill "$$server_pid" >/dev/null 2>&1 || true; \
	wait "$$server_pid" >/dev/null 2>&1 || true; \
	PHOTON_CONFIG="$$tmp/a/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip record list node-b.catofes. --filter identity --verbose | grep -q 'node-b-restarted'; \
	PHOTON_CONFIG="$$tmp/c/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip record list node-b.catofes. --filter identity --verbose | grep -q 'node-b-restarted'; \
	PHOTON_CONFIG="$$tmp/c/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) debug verify node-b.catofes. >/dev/null; \
	echo "Multi-node smoke passed"

# chain-relay-smoke 流程：
# 1. 准备 A-B-C-D 链式拓扑，每个节点只配置相邻 bootstrap。
# 2. 所有 leaf 用最小 join bundle 加入，后续 trust proof 随 snapshot 中继。
# 3. 不预装完整 leaf delegation table，验证 relay 真的能传播必要信任材料。
# 4. A 写入 identity，B/C/D 先启动 daemon，再启动 A。
# 5. 等待 D 收到并 verify A，验证 relay fanout 与周期 digest 收敛。
chain-relay-smoke: build
	@set -eu; \
	tmp="$${TMPDIR:-/tmp}/photon-chain-relay-smoke"; \
	rm -rf "$$tmp"; \
	mkdir -p "$$tmp/admin" "$$tmp/catofes" "$$tmp/a" "$$tmp/b" "$$tmp/c" "$$tmp/d"; \
	printf '%s\n' 'data_dir: '"$$tmp/admin" 'gossip:' '  peer_id: node-admin' '  listen_addr: 127.0.0.1:43473' > "$$tmp/admin/config.yaml"; \
	printf '%s\n' 'data_dir: '"$$tmp/catofes" 'gossip:' '  peer_id: zone-catofes-admin' '  listen_addr: 127.0.0.1:43478' > "$$tmp/catofes/config.yaml"; \
	printf '%s\n' 'data_dir: '"$$tmp/a" 'gossip:' '  peer_id: node-a.catofes.' '  listen_addr: 127.0.0.1:43474' '  bootstrap:' '    - id: node-b.catofes.' '      addr: 127.0.0.1:43475' > "$$tmp/a/config.yaml"; \
	printf '%s\n' 'data_dir: '"$$tmp/b" 'gossip:' '  peer_id: node-b.catofes.' '  listen_addr: 127.0.0.1:43475' '  bootstrap:' '    - id: node-a.catofes.' '      addr: 127.0.0.1:43474' '    - id: node-c.catofes.' '      addr: 127.0.0.1:43476' > "$$tmp/b/config.yaml"; \
	printf '%s\n' 'data_dir: '"$$tmp/c" 'gossip:' '  peer_id: node-c.catofes.' '  listen_addr: 127.0.0.1:43476' '  bootstrap:' '    - id: node-b.catofes.' '      addr: 127.0.0.1:43475' '    - id: node-d.catofes.' '      addr: 127.0.0.1:43477' > "$$tmp/c/config.yaml"; \
	printf '%s\n' 'data_dir: '"$$tmp/d" 'gossip:' '  peer_id: node-d.catofes.' '  listen_addr: 127.0.0.1:43477' '  bootstrap:' '    - id: node-c.catofes.' '      addr: 127.0.0.1:43476' > "$$tmp/d/config.yaml"; \
	PHOTON_CONFIG="$$tmp/admin/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip root init >/dev/null; \
	root_key="$$(PHOTON_CONFIG="$$tmp/admin/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip root pubkey)"; \
	for node in catofes a b c d; do printf '%s\n' 'trusted_root_public_key: '"$$root_key" >> "$$tmp/$$node/config.yaml"; done; \
	PHOTON_CONFIG="$$tmp/catofes/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip keygen "$$tmp/catofes.key.json" >/dev/null; \
	PHOTON_CONFIG="$$tmp/catofes/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip join request catofes. "$$tmp/catofes.key.json" "$$tmp/catofes.request.json" >/dev/null; \
	PHOTON_CONFIG="$$tmp/admin/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip delegate issue --direct "$$tmp/catofes.request.json" "$$tmp/catofes.bundle.json" >/dev/null; \
	PHOTON_CONFIG="$$tmp/catofes/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip join accept --direct "$$tmp/catofes.bundle.json" "$$tmp/catofes.key.json" >/dev/null; \
	for node in a b c d; do PHOTON_CONFIG="$$tmp/$$node/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip keygen "$$tmp/node-$$node.key.json" >/dev/null; PHOTON_CONFIG="$$tmp/$$node/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip join request node-$$node.catofes. "$$tmp/node-$$node.key.json" "$$tmp/node-$$node.request.json" >/dev/null; done; \
	for node in a b c d; do PHOTON_CONFIG="$$tmp/catofes/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip delegate issue --direct "$$tmp/node-$$node.request.json" "$$tmp/node-$$node.bundle.json" >/dev/null; done; \
	for node in a b c d; do PHOTON_CONFIG="$$tmp/$$node/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip join accept --direct "$$tmp/node-$$node.bundle.json" "$$tmp/node-$$node.key.json" >/dev/null; done; \
	PHOTON_CONFIG="$$tmp/a/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip record put --direct node-a.catofes. identity node-a-relay >/dev/null; \
	PHOTON_CONFIG="$$tmp/b/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) daemon --interval 1 >"$$tmp/b.log" 2>&1 & b_pid="$$!"; \
	PHOTON_CONFIG="$$tmp/c/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) daemon --interval 1 >"$$tmp/c.log" 2>&1 & c_pid="$$!"; \
	PHOTON_CONFIG="$$tmp/d/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) daemon --interval 1 >"$$tmp/d.log" 2>&1 & d_pid="$$!"; \
	a_pid=""; \
	trap 'status="$$?"; kill "$$a_pid" "$$b_pid" "$$c_pid" "$$d_pid" >/dev/null 2>&1 || true; if [ "$$status" != 0 ]; then cat "$$tmp/a.log" "$$tmp/b.log" "$$tmp/c.log" "$$tmp/d.log" 2>/dev/null || true; fi; exit "$$status"' EXIT; \
	sleep 1; \
	PHOTON_CONFIG="$$tmp/a/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) daemon --interval 1 >"$$tmp/a.log" 2>&1 & a_pid="$$!"; \
	for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30; do if PHOTON_CONFIG="$$tmp/d/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip record list node-a.catofes. --filter identity --verbose 2>/dev/null | grep -q 'node-a-relay'; then break; fi; sleep 1; done; \
	PHOTON_CONFIG="$$tmp/d/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip record list node-a.catofes. --filter identity --verbose | grep -q 'node-a-relay'; \
	PHOTON_CONFIG="$$tmp/d/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) debug verify node-a.catofes. >/dev/null; \
	kill "$$a_pid" "$$b_pid" "$$c_pid" "$$d_pid" >/dev/null 2>&1 || true; \
	echo "Chain relay smoke passed"

# discovery-smoke 流程：
# 1. 准备 A/B/C 三节点，其中 B 不直接静态 bootstrap 到 C。
# 2. C 写入 identity 和 signed endpoint record。
# 3. 启动 A/B/C 的 daemon，让 endpoint record 经 gossip 传播。
# 4. B 通过 verified active state 发现 C，而不是依赖静态配置。
# 5. 用 debug peer 和 sync status --verbose 断言 discovery 对操作者可见。
discovery-smoke: build
	@set -eu; \
	tmp="$${TMPDIR:-/tmp}/photon-discovery-smoke"; \
	rm -rf "$$tmp"; \
	mkdir -p "$$tmp/admin" "$$tmp/catofes" "$$tmp/a" "$$tmp/b" "$$tmp/c"; \
	printf '%s\n' 'data_dir: '"$$tmp/admin" 'gossip:' '  peer_id: node-admin' '  listen_addr: 127.0.0.1:43493' > "$$tmp/admin/config.yaml"; \
	printf '%s\n' 'data_dir: '"$$tmp/catofes" 'gossip:' '  peer_id: zone-catofes-admin' '  listen_addr: 127.0.0.1:43498' > "$$tmp/catofes/config.yaml"; \
	printf '%s\n' 'data_dir: '"$$tmp/a" 'gossip:' '  peer_id: node-a' '  listen_addr: 127.0.0.1:43494' '  bootstrap:' '    - id: node-b' '      addr: 127.0.0.1:43495' '    - id: node-c' '      addr: 127.0.0.1:43497' > "$$tmp/a/config.yaml"; \
	printf '%s\n' 'data_dir: '"$$tmp/b" 'gossip:' '  peer_id: node-b' '  listen_addr: 127.0.0.1:43495' '  bootstrap:' '    - id: node-a' '      addr: 127.0.0.1:43494' > "$$tmp/b/config.yaml"; \
	printf '%s\n' 'data_dir: '"$$tmp/c" 'gossip:' '  peer_id: node-c' '  listen_addr: 127.0.0.1:43497' '  bootstrap:' '    - id: node-a' '      addr: 127.0.0.1:43494' > "$$tmp/c/config.yaml"; \
	PHOTON_CONFIG="$$tmp/admin/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip root init >/dev/null; \
	root_key="$$(PHOTON_CONFIG="$$tmp/admin/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip root pubkey)"; \
	for node in catofes a b c; do printf '%s\n' 'trusted_root_public_key: '"$$root_key" >> "$$tmp/$$node/config.yaml"; done; \
	PHOTON_CONFIG="$$tmp/catofes/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip keygen "$$tmp/catofes.key.json" >/dev/null; \
	PHOTON_CONFIG="$$tmp/catofes/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip join request catofes. "$$tmp/catofes.key.json" "$$tmp/catofes.request.json" >/dev/null; \
	PHOTON_CONFIG="$$tmp/admin/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip delegate issue --direct "$$tmp/catofes.request.json" "$$tmp/catofes.bundle.json" >/dev/null; \
	PHOTON_CONFIG="$$tmp/catofes/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip join accept --direct "$$tmp/catofes.bundle.json" "$$tmp/catofes.key.json" >/dev/null; \
	for node in a b c; do PHOTON_CONFIG="$$tmp/$$node/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip keygen "$$tmp/node-$$node.key.json" >/dev/null; PHOTON_CONFIG="$$tmp/$$node/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip join request node-$$node.catofes. "$$tmp/node-$$node.key.json" "$$tmp/node-$$node.request.json" >/dev/null; PHOTON_CONFIG="$$tmp/catofes/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip delegate issue --direct "$$tmp/node-$$node.request.json" "$$tmp/node-$$node.bundle.json" >/dev/null; PHOTON_CONFIG="$$tmp/$$node/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip join accept --direct "$$tmp/node-$$node.bundle.json" "$$tmp/node-$$node.key.json" >/dev/null; done; \
	PHOTON_CONFIG="$$tmp/c/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip record put --direct node-c.catofes. identity node-c >/dev/null; \
	PHOTON_CONFIG="$$tmp/a/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) daemon --interval 2 >"$$tmp/a.log" 2>&1 & a_pid="$$!"; \
	sleep 2; \
	PHOTON_CONFIG="$$tmp/b/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) daemon --interval 2 >"$$tmp/b.log" 2>&1 & b_pid="$$!"; \
	PHOTON_CONFIG="$$tmp/c/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) daemon --interval 2 >"$$tmp/c.log" 2>&1 & c_pid="$$!"; \
	trap 'status="$$?"; kill "$$a_pid" "$$b_pid" "$$c_pid" >/dev/null 2>&1 || true; if [ "$$status" != 0 ]; then cat "$$tmp/a.log" "$$tmp/b.log" "$$tmp/c.log" 2>/dev/null || true; fi; exit "$$status"' EXIT; \
	for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do \
		if PHOTON_CONFIG="$$tmp/b/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip record list node-c.catofes. --filter identity 2>/dev/null | grep -q 'identity'; then break; fi; \
		sleep 1; \
	done; \
	sleep 2; \
	PHOTON_CONFIG="$$tmp/b/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip record list node-c.catofes. --filter identity 2>/dev/null | grep -q 'identity'; \
	PHOTON_CONFIG="$$tmp/b/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) debug peer node-c.catofes. | grep -q 'resolved_addr:'; \
	PHOTON_CONFIG="$$tmp/b/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) advanced sync status --verbose | grep -q 'discovered peer=node-c.catofes.'; \
	kill "$$a_pid" "$$b_pid" "$$c_pid" >/dev/null 2>&1 || true; \
	echo "Discovery smoke passed"

# reflector-smoke 流程：
# 1. 不启动 shell 拓扑，直接运行相关 Go 测试。
# 2. 验证 public IP reflector 查询和响应解析。
# 3. 验证 reflector 结果进入本地 endpoint candidate 收集。
# 4. 验证 reflector-derived endpoint 可被签名发布。
reflector-smoke:
	$(GO_ENV) $(GO) test -v ./pkg/core/gossip -run '^Test(QueryPublicIP|CollectLocalEndpointsWithReflectors)'
	$(GO_ENV) $(GO) test -v ./pkg/core/host -run '^TestPlanGossipEndpointIntentRefreshAndGrace$$'

# bootstrap-join-smoke 流程：
# 1. 准备 catofes、node-a、node-b，其中 B 只知道 bootstrap A。
# 2. catofes 以 daemon 启动，提供 UDP gossip 和同端口 TCP object pull。
# 3. A 先从 catofes 同步到 B 的 delegated identity，但还没有 B 的 endpoint。
# 4. A 写入 identity 并启动 daemon，作为 B 的首次接入入口。
# 5. B accept bundle 后启动 daemon，依靠已验证身份入站白名单和 observed reply address。
# 6. 断言 A 看到 B 的 endpoint，B 也看到 A 的既有 record，覆盖首次接入死锁。
bootstrap-join-smoke: build
	@set -eu; \
	tmp="$${TMPDIR:-/tmp}/photon-bootstrap-join-smoke"; \
	rm -rf "$$tmp"; \
	mkdir -p "$$tmp/admin" "$$tmp/catofes" "$$tmp/node-a" "$$tmp/node-b"; \
	catofes_pid=""; a_pid=""; b_pid=""; \
	trap 'status="$$?"; kill "$${catofes_pid:-}" "$${a_pid:-}" "$${b_pid:-}" >/dev/null 2>&1 || true; if [ "$$status" != 0 ]; then cat "$$tmp/catofes.log" "$$tmp/node-a-bootstrap.log" "$$tmp/node-a.log" "$$tmp/node-b.log" 2>/dev/null || true; fi; exit "$$status"' EXIT; \
	printf '%s\n' 'data_dir: '"$$tmp/admin" 'gossip:' '  peer_id: node-admin' '  listen_addr: 127.0.0.1:43500' > "$$tmp/admin/config.yaml"; \
	printf '%s\n' 'data_dir: '"$$tmp/catofes" 'gossip:' '  peer_id: zone-catofes-admin' '  listen_addr: 127.0.0.1:43501' > "$$tmp/catofes/config.yaml"; \
	printf '%s\n' 'data_dir: '"$$tmp/node-a" 'gossip:' '  peer_id: node-a.catofes.' '  listen_addr: 127.0.0.1:43502' '  bootstrap:' '    - id: zone-catofes-admin' '      addr: 127.0.0.1:43501' > "$$tmp/node-a/config.yaml"; \
	printf '%s\n' 'data_dir: '"$$tmp/node-b" 'gossip:' '  peer_id: node-b.catofes.' '  listen_addr: 127.0.0.1:43503' '  bootstrap:' '    - id: node-a.catofes.' '      addr: 127.0.0.1:43502' > "$$tmp/node-b/config.yaml"; \
	PHOTON_CONFIG="$$tmp/admin/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip root init >/dev/null; \
	root_key="$$(PHOTON_CONFIG="$$tmp/admin/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip root pubkey)"; \
	for node in catofes node-a node-b; do printf '%s\n' 'trusted_root_public_key: '"$$root_key" >> "$$tmp/$$node/config.yaml"; done; \
	PHOTON_CONFIG="$$tmp/catofes/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip keygen "$$tmp/catofes.key.json" >/dev/null; \
	PHOTON_CONFIG="$$tmp/catofes/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip join request catofes. "$$tmp/catofes.key.json" "$$tmp/catofes.request.json" >/dev/null; \
	PHOTON_CONFIG="$$tmp/admin/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip delegate issue --direct "$$tmp/catofes.request.json" "$$tmp/catofes.bundle.json" >/dev/null; \
	PHOTON_CONFIG="$$tmp/catofes/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip join accept --direct "$$tmp/catofes.bundle.json" "$$tmp/catofes.key.json" >/dev/null; \
	PHOTON_CONFIG="$$tmp/node-a/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip keygen "$$tmp/node-a.key.json" >/dev/null; \
	PHOTON_CONFIG="$$tmp/node-a/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip join request node-a.catofes. "$$tmp/node-a.key.json" "$$tmp/node-a.request.json" >/dev/null; \
	PHOTON_CONFIG="$$tmp/catofes/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip delegate issue --direct "$$tmp/node-a.request.json" "$$tmp/node-a.bundle.json" >/dev/null; \
	PHOTON_CONFIG="$$tmp/node-a/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip join accept --direct "$$tmp/node-a.bundle.json" "$$tmp/node-a.key.json" >/dev/null; \
	PHOTON_CONFIG="$$tmp/node-b/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip keygen "$$tmp/node-b.key.json" >/dev/null; \
	PHOTON_CONFIG="$$tmp/node-b/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip join request node-b.catofes. "$$tmp/node-b.key.json" "$$tmp/node-b.request.json" >/dev/null; \
	PHOTON_CONFIG="$$tmp/catofes/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip delegate issue --direct "$$tmp/node-b.request.json" "$$tmp/node-b.bundle.json" >/dev/null; \
	PHOTON_CONFIG="$$tmp/catofes/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) daemon --interval 1 >"$$tmp/catofes.log" 2>&1 & catofes_pid="$$!"; \
	sleep 2; \
	if ! kill -0 "$$catofes_pid" >/dev/null 2>&1; then cat "$$tmp/catofes.log"; exit 1; fi; \
	PHOTON_CONFIG="$$tmp/node-a/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) advanced sync once zone-catofes-admin >"$$tmp/node-a-bootstrap.log" 2>&1; \
	PHOTON_CONFIG="$$tmp/node-a/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) debug verify node-b.catofes. >/dev/null; \
	PHOTON_CONFIG="$$tmp/node-a/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip record put --direct node-a.catofes. identity node-a >/dev/null; \
	PHOTON_CONFIG="$$tmp/node-a/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) daemon --interval 1 >"$$tmp/node-a.log" 2>&1 & a_pid="$$!"; \
	sleep 1; \
	PHOTON_CONFIG="$$tmp/node-b/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip join accept --direct "$$tmp/node-b.bundle.json" "$$tmp/node-b.key.json" >/dev/null; \
	PHOTON_CONFIG="$$tmp/node-b/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) daemon --interval 1 >"$$tmp/node-b.log" 2>&1 & b_pid="$$!"; \
	for i in 1 2 3 4 5 6 7 8; do \
		if PHOTON_CONFIG="$$tmp/node-a/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip record list node-b.catofes. --filter sync/endpoint/udp 2>/dev/null | grep -q 'sync/endpoint/udp'; then break; fi; \
		sleep 1; \
	done; \
	PHOTON_CONFIG="$$tmp/node-a/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip record list node-b.catofes. --filter sync/endpoint/udp 2>/dev/null | grep -q 'sync/endpoint/udp'; \
	PHOTON_CONFIG="$$tmp/node-b/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip record list node-a.catofes. --filter identity 2>/dev/null | grep -q 'identity'; \
	kill "$$catofes_pid" "$$a_pid" "$$b_pid" >/dev/null 2>&1 || true; \
	echo "Bootstrap join smoke passed"

# nat-observed-smoke 流程：
# 1. 准备 A/B，其中 B 设置 publish_endpoints: false 模拟 NAT 后节点。
# 2. catofes 以 daemon 启动，提供 UDP gossip 和同端口 TCP object pull。
# 3. A 先从 catofes 同步必要 delegation，再作为 serve 端等待 B。
# 4. B 主动连 A，A 只能记录 observed UDP path，不能生成 durable discovered_addr。
# 5. A 停止 serve 后写入 record，再通过 observed path 对 B 执行 sync once。
# 6. 断言 B 收到 A 的 record，证明无 signed endpoint 时仍可用 verified observed path 返回同步。
nat-observed-smoke: build
	@set -eu; \
	tmp="$${TMPDIR:-/tmp}/photon-nat-observed-smoke"; \
	rm -rf "$$tmp"; \
	mkdir -p "$$tmp/admin" "$$tmp/catofes" "$$tmp/a" "$$tmp/b"; \
	printf '%s\n' 'data_dir: '"$$tmp/admin" 'gossip:' '  peer_id: node-admin' '  listen_addr: 127.0.0.1:43540' > "$$tmp/admin/config.yaml"; \
	printf '%s\n' 'data_dir: '"$$tmp/catofes" 'gossip:' '  peer_id: zone-catofes-admin' '  listen_addr: 127.0.0.1:43541' '  publish_endpoints: false' > "$$tmp/catofes/config.yaml"; \
	printf '%s\n' 'data_dir: '"$$tmp/a" 'gossip:' '  peer_id: node-a.catofes.' '  listen_addr: 127.0.0.1:43542' '  bootstrap:' '    - id: zone-catofes-admin' '      addr: 127.0.0.1:43541' > "$$tmp/a/config.yaml"; \
	printf '%s\n' 'data_dir: '"$$tmp/b" 'gossip:' '  peer_id: node-b.catofes.' '  listen_addr: 127.0.0.1:43543' '  publish_endpoints: false' '  bootstrap:' '    - id: node-a.catofes.' '      addr: 127.0.0.1:43542' > "$$tmp/b/config.yaml"; \
	PHOTON_CONFIG="$$tmp/admin/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip root init >/dev/null; \
	root_key="$$(PHOTON_CONFIG="$$tmp/admin/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip root pubkey)"; \
	for node in catofes a b; do printf '%s\n' 'trusted_root_public_key: '"$$root_key" >> "$$tmp/$$node/config.yaml"; done; \
	PHOTON_CONFIG="$$tmp/catofes/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip keygen "$$tmp/catofes.key.json" >/dev/null; \
	PHOTON_CONFIG="$$tmp/catofes/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip join request catofes. "$$tmp/catofes.key.json" "$$tmp/catofes.request.json" >/dev/null; \
	PHOTON_CONFIG="$$tmp/admin/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip delegate issue --direct "$$tmp/catofes.request.json" "$$tmp/catofes.bundle.json" >/dev/null; \
	PHOTON_CONFIG="$$tmp/catofes/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip join accept --direct "$$tmp/catofes.bundle.json" "$$tmp/catofes.key.json" >/dev/null; \
	for node in a b; do PHOTON_CONFIG="$$tmp/$$node/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip keygen "$$tmp/node-$$node.key.json" >/dev/null; PHOTON_CONFIG="$$tmp/$$node/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip join request node-$$node.catofes. "$$tmp/node-$$node.key.json" "$$tmp/node-$$node.request.json" >/dev/null; PHOTON_CONFIG="$$tmp/catofes/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip delegate issue --direct "$$tmp/node-$$node.request.json" "$$tmp/node-$$node.bundle.json" >/dev/null; PHOTON_CONFIG="$$tmp/$$node/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip join accept --direct "$$tmp/node-$$node.bundle.json" "$$tmp/node-$$node.key.json" >/dev/null; done; \
	PHOTON_CONFIG="$$tmp/catofes/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) daemon --interval 1 >"$$tmp/catofes.log" 2>&1 & catofes_pid="$$!"; \
	a_pid=""; b_pid=""; \
	trap 'status="$$?"; kill "$$catofes_pid" "$$a_pid" "$$b_pid" >/dev/null 2>&1 || true; if [ "$$status" != 0 ]; then cat "$$tmp/catofes.log" "$$tmp/a.log" "$$tmp/b.log" "$$tmp/put.out" "$$tmp/a-to-b.log" 2>/dev/null || true; fi; exit "$$status"' EXIT; \
	sleep 1; \
	PHOTON_CONFIG="$$tmp/a/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) advanced sync once zone-catofes-admin >/dev/null; \
	PHOTON_CONFIG="$$tmp/a/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) debug verify node-b.catofes. >/dev/null; \
	kill "$$catofes_pid" >/dev/null 2>&1 || true; wait "$$catofes_pid" >/dev/null 2>&1 || true; \
	PHOTON_CONFIG="$$tmp/a/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) advanced sync serve >"$$tmp/a.log" 2>&1 & a_pid="$$!"; \
	sleep 1; \
	if ! kill -0 "$$a_pid" >/dev/null 2>&1; then cat "$$tmp/a.log"; exit 1; fi; \
	PHOTON_CONFIG="$$tmp/b/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) daemon --interval 60 >"$$tmp/b.log" 2>&1 & b_pid="$$!"; \
	for i in 1 2 3 4 5 6 7 8; do if PHOTON_CONFIG="$$tmp/a/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) debug peer node-b.catofes. 2>/dev/null | grep -q 'observed_status: active'; then break; fi; sleep 1; done; \
	PHOTON_CONFIG="$$tmp/a/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) debug peer node-b.catofes. | grep -q 'observed_addr: 127.0.0.1:43543'; \
	PHOTON_CONFIG="$$tmp/a/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) debug peer node-b.catofes. | grep -q 'observed_status: active'; \
	if PHOTON_CONFIG="$$tmp/a/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) debug peer node-b.catofes. | grep -q 'discovered_addr: 127.0.0.1:43543'; then exit 1; fi; \
	kill "$$a_pid" >/dev/null 2>&1 || true; wait "$$a_pid" >/dev/null 2>&1 || true; a_pid=""; \
	PHOTON_CONFIG="$$tmp/a/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip record put --direct node-a.catofes. identity node-a-observed >"$$tmp/put.out"; \
	PHOTON_CONFIG="$$tmp/a/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) advanced sync once node-b.catofes. >"$$tmp/a-to-b.log" 2>&1 || grep -q 'pending zones' "$$tmp/a-to-b.log"; \
	for i in 1 2 3 4 5 6 7 8; do if PHOTON_CONFIG="$$tmp/b/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip record list node-a.catofes. --filter identity --verbose 2>/dev/null | grep -q 'node-a-observed'; then break; fi; sleep 1; done; \
	PHOTON_CONFIG="$$tmp/b/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip record list node-a.catofes. --filter identity --verbose 2>/dev/null | grep -q 'node-a-observed'; \
	PHOTON_CONFIG="$$tmp/b/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) debug verify node-a.catofes. >/dev/null; \
	kill "$$a_pid" "$$b_pid" >/dev/null 2>&1 || true; \
	echo "NAT observed path smoke passed"

# nat-daemon-observed-smoke 流程：
# 1. 准备 A/B，其中 B 禁用 endpoint 发布，A 使用 advertise_addr。
# 2. catofes 以 daemon 启动，提供 UDP gossip 和同端口 TCP object pull。
# 3. A 先从 catofes 同步 delegation，再启动 A/B daemon。
# 4. 断言 A 对 B 只记录 observed_addr/observed_status，不产生 discovered_addr。
# 5. 通过 A 的 control socket 写入 record。
# 6. 等待 B 收到并 verify A，确保 daemon 路径与 direct CLI 的 NAT observed 行为一致。
nat-daemon-observed-smoke: build
	@set -eu; \
	tmp="$${TMPDIR:-/tmp}/photon-nat-daemon-observed-smoke"; \
	rm -rf "$$tmp"; \
	mkdir -p "$$tmp/admin" "$$tmp/catofes" "$$tmp/a" "$$tmp/b"; \
	printf '%s\n' 'data_dir: '"$$tmp/admin" 'gossip:' '  peer_id: node-admin' '  listen_addr: 127.0.0.1:43560' > "$$tmp/admin/config.yaml"; \
	printf '%s\n' 'data_dir: '"$$tmp/catofes" 'gossip:' '  peer_id: zone-catofes-admin' '  listen_addr: 127.0.0.1:43561' '  publish_endpoints: false' > "$$tmp/catofes/config.yaml"; \
	printf '%s\n' 'data_dir: '"$$tmp/a" 'gossip:' '  peer_id: node-a.catofes.' '  listen_addr: 127.0.0.1:43562' '  advertise_addr: 127.0.0.1:43562' '  bootstrap:' '    - id: zone-catofes-admin' '      addr: 127.0.0.1:43561' > "$$tmp/a/config.yaml"; \
	printf '%s\n' 'data_dir: '"$$tmp/b" 'gossip:' '  peer_id: node-b.catofes.' '  listen_addr: 127.0.0.1:43563' '  publish_endpoints: false' '  bootstrap:' '    - id: node-a.catofes.' '      addr: 127.0.0.1:43562' > "$$tmp/b/config.yaml"; \
	PHOTON_CONFIG="$$tmp/admin/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip root init >/dev/null; \
	root_key="$$(PHOTON_CONFIG="$$tmp/admin/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip root pubkey)"; \
	for node in catofes a b; do printf '%s\n' 'trusted_root_public_key: '"$$root_key" >> "$$tmp/$$node/config.yaml"; done; \
	PHOTON_CONFIG="$$tmp/catofes/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip keygen "$$tmp/catofes.key.json" >/dev/null; \
	PHOTON_CONFIG="$$tmp/catofes/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip join request catofes. "$$tmp/catofes.key.json" "$$tmp/catofes.request.json" >/dev/null; \
	PHOTON_CONFIG="$$tmp/admin/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip delegate issue --direct "$$tmp/catofes.request.json" "$$tmp/catofes.bundle.json" >/dev/null; \
	PHOTON_CONFIG="$$tmp/catofes/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip join accept --direct "$$tmp/catofes.bundle.json" "$$tmp/catofes.key.json" >/dev/null; \
	for node in a b; do PHOTON_CONFIG="$$tmp/$$node/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip keygen "$$tmp/node-$$node.key.json" >/dev/null; PHOTON_CONFIG="$$tmp/$$node/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip join request node-$$node.catofes. "$$tmp/node-$$node.key.json" "$$tmp/node-$$node.request.json" >/dev/null; PHOTON_CONFIG="$$tmp/catofes/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip delegate issue --direct "$$tmp/node-$$node.request.json" "$$tmp/node-$$node.bundle.json" >/dev/null; PHOTON_CONFIG="$$tmp/$$node/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip join accept --direct "$$tmp/node-$$node.bundle.json" "$$tmp/node-$$node.key.json" >/dev/null; done; \
	PHOTON_CONFIG="$$tmp/catofes/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) daemon --interval 1 >"$$tmp/catofes.log" 2>&1 & catofes_pid="$$!"; \
	a_pid=""; b_pid=""; \
	trap 'status="$$?"; kill "$$catofes_pid" "$$a_pid" "$$b_pid" >/dev/null 2>&1 || true; if [ "$$status" != 0 ]; then cat "$$tmp/catofes.log" "$$tmp/a.log" "$$tmp/b.log" "$$tmp/record-put.out" 2>/dev/null || true; fi; exit "$$status"' EXIT; \
	sleep 1; \
	PHOTON_CONFIG="$$tmp/a/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) advanced sync once zone-catofes-admin >/dev/null; \
	PHOTON_CONFIG="$$tmp/a/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) debug verify node-b.catofes. >/dev/null; \
	kill "$$catofes_pid" >/dev/null 2>&1 || true; wait "$$catofes_pid" >/dev/null 2>&1 || true; catofes_pid=""; \
	PHOTON_CONTROL_SOCKET="$$tmp/a/photon.sock" PHOTON_CONFIG="$$tmp/a/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) daemon --interval 60 >"$$tmp/a.log" 2>&1 & a_pid="$$!"; \
	sleep 2; \
	PHOTON_CONTROL_SOCKET="$$tmp/b/photon.sock" PHOTON_CONFIG="$$tmp/b/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) daemon --interval 60 >"$$tmp/b.log" 2>&1 & b_pid="$$!"; \
	for i in 1 2 3 4 5; do if [ -S "$$tmp/a/photon.sock" ] && [ -S "$$tmp/b/photon.sock" ]; then break; fi; sleep 1; done; \
	[ -S "$$tmp/a/photon.sock" ]; \
	[ -S "$$tmp/b/photon.sock" ]; \
	for i in 1 2 3 4 5 6 7 8; do if PHOTON_CONFIG="$$tmp/a/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) debug peer node-b.catofes. 2>/dev/null | grep -q 'observed_status: active'; then break; fi; sleep 1; done; \
	PHOTON_CONFIG="$$tmp/a/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) debug peer node-b.catofes. | grep -q 'observed_addr: 127.0.0.1:43563'; \
	PHOTON_CONFIG="$$tmp/a/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) debug peer node-b.catofes. | grep -q 'observed_status: active'; \
	if PHOTON_CONFIG="$$tmp/a/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) debug peer node-b.catofes. | grep -q 'discovered_addr: 127.0.0.1:43563'; then echo "FAIL: B should not have discovered_addr" >&2; exit 1; fi; \
	PHOTON_CONTROL_SOCKET="$$tmp/a/photon.sock" PHOTON_CONFIG="$$tmp/a/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip record put node-a.catofes. identity node-a-nat-daemon >"$$tmp/record-put.out"; \
	grep -q 'via daemon' "$$tmp/record-put.out"; \
	for i in 1 2 3 4 5 6 7 8 9 10; do if PHOTON_CONFIG="$$tmp/b/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip record list node-a.catofes. --filter identity --verbose 2>/dev/null | grep -q 'node-a-nat-daemon'; then break; fi; sleep 1; done; \
	PHOTON_CONFIG="$$tmp/b/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip record list node-a.catofes. --filter identity --verbose 2>/dev/null | grep -q 'node-a-nat-daemon'; \
	PHOTON_CONFIG="$$tmp/b/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) debug verify node-a.catofes. >/dev/null; \
	kill "$$a_pid" "$$b_pid" >/dev/null 2>&1 || true; \
	echo "NAT daemon observed path smoke passed"

# delegation-revoke-smoke 流程：
# 1. 准备 A/B/C 和 catofes，其中 B 先发布 identity 与 endpoint record。
# 2. 所有 leaf 用最小 join bundle 加入，后续对端状态和撤销通过同步传播。
# 3. 让 A/C 通过同步信任 B，并确认 B endpoint 进入 discovered peers。
# 4. catofes. 对 node-b.catofes. 写入 parent-authoritative revocation。
# 5. A/C 从 catofes 同步 revocation 后，verify B 必须失败且 debug zone 显示 revoked。
# 6. 断言 A 的 discovered peers 不再包含 B，防止撤销节点通过旧 endpoint 复活。
delegation-revoke-smoke: build
	@set -eu; \
	tmp="$${TMPDIR:-/tmp}/photon-delegation-revoke-smoke"; \
	rm -rf "$$tmp"; \
	mkdir -p "$$tmp/admin" "$$tmp/catofes" "$$tmp/a" "$$tmp/b" "$$tmp/c"; \
	printf '%s\n' 'data_dir: '"$$tmp/admin" 'gossip:' '  peer_id: node-admin' '  listen_addr: 127.0.0.1:43510' > "$$tmp/admin/config.yaml"; \
	printf '%s\n' 'data_dir: '"$$tmp/catofes" 'gossip:' '  peer_id: zone-catofes-admin' '  listen_addr: 127.0.0.1:43511' > "$$tmp/catofes/config.yaml"; \
	printf '%s\n' 'data_dir: '"$$tmp/a" 'gossip:' '  peer_id: node-a.catofes.' '  listen_addr: 127.0.0.1:43512' '  bootstrap:' '    - id: zone-catofes-admin' '      addr: 127.0.0.1:43511' '    - id: node-b.catofes.' '      addr: 127.0.0.1:43513' '    - id: node-c.catofes.' '      addr: 127.0.0.1:43514' > "$$tmp/a/config.yaml"; \
	printf '%s\n' 'data_dir: '"$$tmp/b" 'gossip:' '  peer_id: node-b.catofes.' '  listen_addr: 127.0.0.1:43513' '  bootstrap:' '    - id: node-a.catofes.' '      addr: 127.0.0.1:43512' > "$$tmp/b/config.yaml"; \
	printf '%s\n' 'data_dir: '"$$tmp/c" 'gossip:' '  peer_id: node-c.catofes.' '  listen_addr: 127.0.0.1:43514' '  bootstrap:' '    - id: zone-catofes-admin' '      addr: 127.0.0.1:43511' '    - id: node-a.catofes.' '      addr: 127.0.0.1:43512' > "$$tmp/c/config.yaml"; \
	PHOTON_CONFIG="$$tmp/admin/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip root init >/dev/null; \
	root_key="$$(PHOTON_CONFIG="$$tmp/admin/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip root pubkey)"; \
	for node in catofes a b c; do printf '%s\n' 'trusted_root_public_key: '"$$root_key" >> "$$tmp/$$node/config.yaml"; done; \
	PHOTON_CONFIG="$$tmp/catofes/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip keygen "$$tmp/catofes.key.json" >/dev/null; \
	PHOTON_CONFIG="$$tmp/catofes/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip join request catofes. "$$tmp/catofes.key.json" "$$tmp/catofes.request.json" >/dev/null; \
	PHOTON_CONFIG="$$tmp/admin/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip delegate issue --direct "$$tmp/catofes.request.json" "$$tmp/catofes.bundle.json" >/dev/null; \
	PHOTON_CONFIG="$$tmp/catofes/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip join accept --direct "$$tmp/catofes.bundle.json" "$$tmp/catofes.key.json" >/dev/null; \
	for node in a b c; do PHOTON_CONFIG="$$tmp/$$node/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip keygen "$$tmp/node-$$node.key.json" >/dev/null; PHOTON_CONFIG="$$tmp/$$node/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip join request node-$$node.catofes. "$$tmp/node-$$node.key.json" "$$tmp/node-$$node.request.json" >/dev/null; done; \
	for node in b c a; do PHOTON_CONFIG="$$tmp/catofes/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip delegate issue --direct "$$tmp/node-$$node.request.json" "$$tmp/node-$$node.bundle.json" >/dev/null; done; \
	for node in a b c; do PHOTON_CONFIG="$$tmp/$$node/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip join accept --direct "$$tmp/node-$$node.bundle.json" "$$tmp/node-$$node.key.json" >/dev/null; done; \
	PHOTON_CONFIG="$$tmp/b/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip record put --direct node-b.catofes. identity node-b >/dev/null; \
	PHOTON_CONFIG="$$tmp/b/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) daemon --interval 60 >"$$tmp/b-seed.log" 2>&1 & b_seed_pid="$$!"; \
	sleep 1; kill "$$b_seed_pid" >/dev/null 2>&1 || true; wait "$$b_seed_pid" >/dev/null 2>&1 || true; \
	PHOTON_CONFIG="$$tmp/a/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) daemon --interval 60 >"$$tmp/a.log" 2>&1 & a_pid="$$!"; \
	catofes_pid=""; \
	trap 'status="$$?"; kill "$$a_pid" "$$catofes_pid" >/dev/null 2>&1 || true; if [ "$$status" != 0 ]; then cat "$$tmp/a.log" "$$tmp/catofes.log" "$$tmp/b-to-a.log" "$$tmp/c-to-a.log" "$$tmp/a-from-catofes.log" "$$tmp/c-from-catofes.log" 2>/dev/null || true; fi; exit "$$status"' EXIT; \
	sleep 1; \
	for i in 1 2 3 4 5; do \
		PHOTON_CONFIG="$$tmp/b/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) advanced sync once node-a.catofes. >"$$tmp/b-to-a.log" 2>&1 || grep -Eq 'pending zones|sync receive timed out' "$$tmp/b-to-a.log"; \
		if PHOTON_CONFIG="$$tmp/a/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) debug zone node-b.catofes. >/dev/null 2>&1; then break; fi; \
		sleep 1; \
	done; \
	for i in 1 2 3 4 5; do \
		PHOTON_CONFIG="$$tmp/c/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) advanced sync once node-a.catofes. >"$$tmp/c-to-a.log" 2>&1 || grep -Eq 'pending zones|sync receive timed out' "$$tmp/c-to-a.log"; \
		if PHOTON_CONFIG="$$tmp/c/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) debug zone node-b.catofes. >/dev/null 2>&1; then break; fi; \
		sleep 1; \
	done; \
	PHOTON_CONFIG="$$tmp/a/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) debug verify node-b.catofes. >/dev/null; \
	PHOTON_CONFIG="$$tmp/c/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) debug verify node-b.catofes. >/dev/null; \
	PHOTON_CONFIG="$$tmp/c/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) advanced sync status --verbose | grep -q 'discovered peer=node-b.catofes.'; \
	kill "$$a_pid" >/dev/null 2>&1 || true; \
	wait "$$a_pid" >/dev/null 2>&1 || true; \
	PHOTON_CONFIG="$$tmp/catofes/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip delegate revoke --direct node-b.catofes. retired >/dev/null; \
	PHOTON_CONFIG="$$tmp/catofes/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) daemon --interval 60 >"$$tmp/catofes.log" 2>&1 & catofes_pid="$$!"; \
	sleep 1; \
	for node in a c; do \
		for i in 1 2 3; do \
			PHOTON_CONFIG="$$tmp/$$node/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) advanced sync once zone-catofes-admin >"$$tmp/$$node-from-catofes.log" 2>&1 || grep -Eq 'pending zones|gossip peer quota exceeded|sync receive timed out' "$$tmp/$$node-from-catofes.log"; \
			if PHOTON_CONFIG="$$tmp/$$node/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) debug zone node-b.catofes. 2>/dev/null | grep -q 'revoked: true'; then break; fi; \
			sleep 1; \
		done; \
	done; \
	if PHOTON_CONFIG="$$tmp/a/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) debug verify node-b.catofes. >/dev/null 2>&1; then exit 1; fi; \
	if PHOTON_CONFIG="$$tmp/c/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) debug verify node-b.catofes. >/dev/null 2>&1; then exit 1; fi; \
	PHOTON_CONFIG="$$tmp/a/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) debug zone node-b.catofes. | grep -q 'revoked: true'; \
	PHOTON_CONFIG="$$tmp/c/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) debug zone node-b.catofes. | grep -q 'revoked: true'; \
	if PHOTON_CONFIG="$$tmp/c/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) advanced sync status --verbose | grep -q 'discovered peer=node-b.catofes.'; then exit 1; fi; \
	kill "$$a_pid" "$$catofes_pid" >/dev/null 2>&1 || true; \
	echo "Delegation revoke smoke passed"

# object-pull-smoke 流程：
# 1. 准备 A/B 两节点并启动双方 daemon。
# 2. A 通过 control socket 写入 3000-byte bigdata record。
# 3. 该 record 超过默认 1200-byte UDP datagram budget，不应通过超大 UDP 发送。
# 4. B 必须通过 digest/metadata gossip 触发 TCP object pull 拉取完整对象。
# 5. 断言 B 能看到 bigdata 并 verify A，证明不依赖 IP fragmentation。
object-pull-smoke: build
	@set -eu; \
	tmp="$${TMPDIR:-/tmp}/photon-object-pull-smoke"; \
	rm -rf "$$tmp"; \
	mkdir -p "$$tmp/admin" "$$tmp/catofes" "$$tmp/a" "$$tmp/b"; \
	printf '%s\n' 'data_dir: '"$$tmp/admin" 'gossip:' '  peer_id: node-admin' '  listen_addr: 127.0.0.1:43540' > "$$tmp/admin/config.yaml"; \
	printf '%s\n' 'data_dir: '"$$tmp/catofes" 'gossip:' '  peer_id: zone-catofes-admin' '  listen_addr: 127.0.0.1:43541' > "$$tmp/catofes/config.yaml"; \
	printf '%s\n' 'data_dir: '"$$tmp/a" 'gossip:' '  peer_id: node-a.catofes.' '  listen_addr: 127.0.0.1:43542' '  advertise_addr: 127.0.0.1:43542' '  bootstrap:' '    - id: node-b.catofes.' '      addr: 127.0.0.1:43543' > "$$tmp/a/config.yaml"; \
	printf '%s\n' 'data_dir: '"$$tmp/b" 'gossip:' '  peer_id: node-b.catofes.' '  listen_addr: 127.0.0.1:43543' '  advertise_addr: 127.0.0.1:43543' '  bootstrap:' '    - id: node-a.catofes.' '      addr: 127.0.0.1:43542' > "$$tmp/b/config.yaml"; \
	PHOTON_CONFIG="$$tmp/admin/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip root init >/dev/null; \
	root_key="$$(PHOTON_CONFIG="$$tmp/admin/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip root pubkey)"; \
	for node in catofes a b; do printf '%s\n' 'trusted_root_public_key: '"$$root_key" >> "$$tmp/$$node/config.yaml"; done; \
	PHOTON_CONFIG="$$tmp/catofes/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip keygen "$$tmp/catofes.key.json" >/dev/null; \
	PHOTON_CONFIG="$$tmp/catofes/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip join request catofes. "$$tmp/catofes.key.json" "$$tmp/catofes.request.json" >/dev/null; \
	PHOTON_CONFIG="$$tmp/admin/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip delegate issue --direct "$$tmp/catofes.request.json" "$$tmp/catofes.bundle.json" >/dev/null; \
	PHOTON_CONFIG="$$tmp/catofes/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip join accept --direct "$$tmp/catofes.bundle.json" "$$tmp/catofes.key.json" >/dev/null; \
	for node in a b; do PHOTON_CONFIG="$$tmp/$$node/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip keygen "$$tmp/node-$$node.key.json" >/dev/null; PHOTON_CONFIG="$$tmp/$$node/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip join request node-$$node.catofes. "$$tmp/node-$$node.key.json" "$$tmp/node-$$node.request.json" >/dev/null; PHOTON_CONFIG="$$tmp/catofes/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip delegate issue --direct "$$tmp/node-$$node.request.json" "$$tmp/node-$$node.bundle.json" >/dev/null; PHOTON_CONFIG="$$tmp/$$node/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip join accept --direct "$$tmp/node-$$node.bundle.json" "$$tmp/node-$$node.key.json" >/dev/null; done; \
	PHOTON_CONTROL_SOCKET="$$tmp/b/photon.sock" PHOTON_CONFIG="$$tmp/b/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) daemon --interval 30 >"$$tmp/b.log" 2>&1 & b_pid="$$!"; \
	sleep 4; \
	PHOTON_CONTROL_SOCKET="$$tmp/a/photon.sock" PHOTON_CONFIG="$$tmp/a/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) daemon --interval 30 >"$$tmp/a.log" 2>&1 & a_pid="$$!"; \
	trap 'status="$$?"; kill "$$a_pid" "$$b_pid" >/dev/null 2>&1 || true; if [ "$$status" != 0 ]; then cat "$$tmp/a.log" "$$tmp/b.log" "$$tmp/record-put.out" 2>/dev/null || true; fi; exit "$$status"' EXIT; \
	for i in 1 2 3 4 5; do if [ -S "$$tmp/a/photon.sock" ] && [ -S "$$tmp/b/photon.sock" ]; then break; fi; sleep 1; done; \
	[ -S "$$tmp/a/photon.sock" ]; \
	[ -S "$$tmp/b/photon.sock" ]; \
	large_value="$$(perl -e 'print "x" x 3000')"; \
	PHOTON_CONTROL_SOCKET="$$tmp/a/photon.sock" PHOTON_CONFIG="$$tmp/a/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip record put node-a.catofes. bigdata "$$large_value" test.data >"$$tmp/record-put.out"; \
	grep -q 'via daemon' "$$tmp/record-put.out"; \
	sleep 3; \
	PHOTON_CONFIG="$$tmp/a/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip record list node-a.catofes. --filter bigdata | grep -q 'bigdata'; \
	for i in $$(seq 1 30); do if PHOTON_CONFIG="$$tmp/b/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip record list node-a.catofes. --filter bigdata 2>/dev/null | grep -q 'bigdata'; then break; fi; sleep 1; done; \
	PHOTON_CONFIG="$$tmp/b/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip record list node-a.catofes. --filter bigdata 2>/dev/null | grep -q 'bigdata' || { PHOTON_CONFIG="$$tmp/b/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip record list node-a.catofes.; exit 1; }; \
	PHOTON_CONFIG="$$tmp/b/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) debug verify node-a.catofes. >/dev/null; \
	kill "$$a_pid" "$$b_pid" >/dev/null 2>&1 || true; \
	echo "Object pull smoke passed"

# chunk-fallback-smoke 流程：
# 1. 准备 A/B（拓扑同 object-pull-smoke，互相 bootstrap）。
# 2. B 的 TCP object pull 端口被临时抢占，导致 B 的 daemon 启动时
#    object pull server 绑定失败（daemon 继续运行，只剩 UDP）。
# 3. A 正常启动 daemon（UDP+TCP）。
# 4. B 通过 control socket 写入 3000-byte bigdata record。
# 5. B 的 UDP gossip 向 A 发出 announce/digest；A 尝试 TCP object pull B
#    失败（connection refused），触发 chunk fallback 路径。
# 6. A 发送 fetch_zone 带 ChunkFallback=true；B 将 zone snapshot 拆成
#    多个 UDP object_chunk 发给 A。
# 7. 断言 A 收到 bigdata，且 A 的 daemon 日志确认该 zone 经 UDP chunks apply。
chunk-fallback-smoke: build
	$(GO_ENV) $(GO) test ./pkg/core/gossip -run '^Test(SentChunkCache|MissingChunkIndexes|ChunkAssemblyQuietNACK)'
	@set -eu; \
	tmp="$${TMPDIR:-/tmp}/photon-chunk-fallback-smoke"; \
	rm -rf "$$tmp"; \
	mkdir -p "$$tmp/admin" "$$tmp/catofes" "$$tmp/a" "$$tmp/b"; \
	printf '%s\n' 'data_dir: '"$$tmp/admin" 'gossip:' '  peer_id: node-admin' '  listen_addr: 127.0.0.1:43590' > "$$tmp/admin/config.yaml"; \
	printf '%s\n' 'data_dir: '"$$tmp/catofes" 'gossip:' '  peer_id: catofes.' '  listen_addr: 127.0.0.1:43591' > "$$tmp/catofes/config.yaml"; \
	printf '%s\n' 'data_dir: '"$$tmp/a" 'gossip:' '  peer_id: node-a.catofes.' '  listen_addr: 127.0.0.1:43592' '  advertise_addr: 127.0.0.1:43592' '  bootstrap:' '    - id: node-b.catofes.' '      addr: 127.0.0.1:43593' > "$$tmp/a/config.yaml"; \
	printf '%s\n' 'data_dir: '"$$tmp/b" 'gossip:' '  peer_id: node-b.catofes.' '  listen_addr: 127.0.0.1:43593' '  advertise_addr: 127.0.0.1:43593' '  bootstrap:' '    - id: node-a.catofes.' '      addr: 127.0.0.1:43592' > "$$tmp/b/config.yaml"; \
	PHOTON_CONFIG="$$tmp/admin/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip root init >/dev/null; \
	root_key="$$(PHOTON_CONFIG="$$tmp/admin/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip root pubkey)"; \
	for node in catofes a b; do printf '%s\n' 'trusted_root_public_key: '"$$root_key" >> "$$tmp/$$node/config.yaml"; done; \
	PHOTON_CONFIG="$$tmp/catofes/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip keygen "$$tmp/catofes.key.json" >/dev/null; \
	PHOTON_CONFIG="$$tmp/catofes/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip join request catofes. "$$tmp/catofes.key.json" "$$tmp/catofes.request.json" >/dev/null; \
	PHOTON_CONFIG="$$tmp/admin/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip delegate issue --direct "$$tmp/catofes.request.json" "$$tmp/catofes.bundle.json" >/dev/null; \
	PHOTON_CONFIG="$$tmp/catofes/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip join accept --direct "$$tmp/catofes.bundle.json" "$$tmp/catofes.key.json" >/dev/null; \
	for node in a b; do PHOTON_CONFIG="$$tmp/$$node/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip keygen "$$tmp/node-$$node.key.json" >/dev/null; PHOTON_CONFIG="$$tmp/$$node/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip join request node-$$node.catofes. "$$tmp/node-$$node.key.json" "$$tmp/node-$$node.request.json" >/dev/null; PHOTON_CONFIG="$$tmp/catofes/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip delegate issue --direct "$$tmp/node-$$node.request.json" "$$tmp/node-$$node.bundle.json" >/dev/null; PHOTON_CONFIG="$$tmp/$$node/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip join accept --direct "$$tmp/node-$$node.bundle.json" "$$tmp/node-$$node.key.json" >/dev/null; done; \
	perl -e 'use IO::Socket::INET; my $$s = IO::Socket::INET->new(LocalAddr => "127.0.0.1", LocalPort => 43593, Proto => "tcp", Listen => 1, Reuse => 1) or die $$!; sleep 3600' & tcp_blocker_pid="$$!"; \
	sleep 0.5; \
	PHOTON_CONTROL_SOCKET="$$tmp/b/photon.sock" PHOTON_CONFIG="$$tmp/b/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) daemon --interval 30 >"$$tmp/b.log" 2>&1 & b_pid="$$!"; \
	sleep 2; \
	kill "$$tcp_blocker_pid" >/dev/null 2>&1 || true; wait "$$tcp_blocker_pid" >/dev/null 2>&1 || true; \
	PHOTON_CONTROL_SOCKET="$$tmp/a/photon.sock" PHOTON_CONFIG="$$tmp/a/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) daemon --interval 30 >"$$tmp/a.log" 2>&1 & a_pid="$$!"; \
	trap 'status="$$?"; kill "$$a_pid" "$$b_pid" >/dev/null 2>&1 || true; if [ "$$status" != 0 ]; then cat "$$tmp/a.log" "$$tmp/b.log" "$$tmp/record-put.out" 2>/dev/null || true; fi; exit "$$status"' EXIT; \
	for i in 1 2 3 4 5; do if [ -S "$$tmp/a/photon.sock" ] && [ -S "$$tmp/b/photon.sock" ]; then break; fi; sleep 1; done; \
	[ -S "$$tmp/a/photon.sock" ]; \
	[ -S "$$tmp/b/photon.sock" ]; \
	large_value="$$(perl -e 'print "x" x 3000')"; \
	PHOTON_CONTROL_SOCKET="$$tmp/b/photon.sock" PHOTON_CONFIG="$$tmp/b/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip record put node-b.catofes. bigdata "$$large_value" test.data >"$$tmp/record-put.out"; \
	grep -q 'via daemon' "$$tmp/record-put.out"; \
	for i in 1 2 3 4 5 6 7 8 9 10; do if PHOTON_CONFIG="$$tmp/a/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip record list node-b.catofes. --filter bigdata 2>/dev/null | grep -q 'bigdata'; then break; fi; sleep 1; done; \
	PHOTON_CONFIG="$$tmp/a/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip record list node-b.catofes. --filter bigdata 2>/dev/null | grep -q 'bigdata' || { PHOTON_CONFIG="$$tmp/a/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) gossip record list node-b.catofes.; exit 1; }; \
	PHOTON_CONFIG="$$tmp/a/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) debug verify node-b.catofes. >/dev/null; \
	grep -q 'event=zone_applied.*via=udp_chunks.*zone=node-b.catofes\.' "$$tmp/a.log"; \
	kill "$$a_pid" "$$b_pid" >/dev/null 2>&1 || true; \
	echo "Chunk fallback smoke passed"

help:
	@echo "Available targets:"
	@echo "  build   - Build the photon binary to $(BUILD_DIR)/"
	@echo "  clean   - Remove build artifacts"
	@echo "  test    - Run all tests"
	@echo "  fmt     - Format Go source code"
	@echo "  vet     - Run go vet"
	@echo "  check   - Run fmt, vet, test, and build"
	@echo "  photon-windows-build - Cross-build Photon Windows for windows/amd64"
	@echo "  photon-windows-test - Run Photon Windows portable tests"
	@echo "  release-check - Validate VERSION/repository state and run release tests"
	@echo "  release-tag - Create local v<VERSION> tag after release checks"
	@echo "  release-push - Push the local release tag to $(RELEASE_REMOTE)"
	@echo "  install - Install photon to GOPATH/bin"
	@echo "  run     - Build and run photon"
	@echo "  smoke   - Run all smoke tests"
	@echo "  smoke-all - Run all smoke tests"
	@echo "  root-smoke - Run all real root data-plane smoke tests (requires root, NOT in smoke-all)"
	@echo "  join-smoke - Run root/delegation/join smoke test"
	@echo "  zone-sort-smoke - Verify hierarchical dot/hyphen zone ordering"
	@echo "  record-view-smoke - Verify human record values and verbose metadata"
	@echo "  cli-surface-smoke - Verify gossip/links/route/firewall/service show hierarchy and tables"
	@echo "  phase1-smoke - Run a local two-peer gossip smoke test"
	@echo "  phase2-smoke - Run bidirectional two-peer sync smoke test"
	@echo "  phase2-run-smoke - Run daemon reconnect/recovery smoke test"
	@echo "  phase3-daemon-smoke - Run daemon control write and sync smoke test"
	@echo "  phase3-daemon-fallback-smoke - Run daemon-off direct write recovery smoke test"
	@echo "  multi-node-smoke - Run three-node transitive sync smoke test"
	@echo "  chain-relay-smoke - Run four-node chain relay fanout smoke test"
	@echo "  discovery-smoke - Run endpoint discovery smoke test"
	@echo "  reflector-smoke - Run public IP reflector endpoint smoke test"
	@echo "  bootstrap-join-smoke - Run new-node bootstrap admission smoke test"
	@echo "  nat-observed-smoke - Run NAT-style verified observed UDP path smoke test"
	@echo "  nat-daemon-observed-smoke - Run daemon-based NAT observed path smoke test"
	@echo "  admin-daemon-smoke - Run admin daemon delegation issue/grant/revoke smoke test"
	@echo "  delegation-revoke-smoke - Run delegation revocation convergence smoke test"
	@echo "  object-pull-smoke - Run large-record object-pull over TCP smoke test"
	@echo "  chunk-fallback-smoke - Run large-record UDP chunk fallback when TCP object pull is unreachable"
	@echo "  ipsec-policy-smoke - Run IPsec mesh policy URI rule planner smoke test"
	@echo "  ipsec-dry-run-smoke - Run IPsec planner + fake driver reconcile smoke test"
	@echo "  routing-dry-run-smoke - Run Phase 5 routing dry-run smoke test"
	@echo "  firewall-dry-run-smoke - Run Phase 6.3 firewall planner + config dry-run smoke test"
	@echo "  firewall-smoke - Run real nftables/iptables firewall smoke (requires root, NOT in smoke-all)"
	@echo "  firewall-container-smoke - Run firewall smoke in privileged container"
	@echo "  health-smoke - Run Phase 6.6 health/metrics smoke with real BIRD cutover gate (requires root, NOT in smoke-all)"
	@echo "  health-fault-smoke - Run health/BIRD smoke with tc fault injection and recovery (requires root, NOT in smoke-all)"
	@echo "  health-fault-container-smoke - Run health fault-injection smoke in privileged container"
	@echo "  services-smoke - Run Phase 8 Docker bridge, SOCKS5, Babel and Anycast root smoke (requires root + Docker)"
	@echo "  peer-lifecycle-smoke - Run Phase 6.4 peer lifecycle unit smoke test"
	@echo "  revocation-cleanup-smoke - Run Phase 6.5 revocation impact + deny-first cleanup smoke test"
	@echo "  revocation-data-plane-smoke - Run combined Phase 6.5 firewall+BIRD+StrongSwan smoke (requires root, NOT in smoke-all)"
	@echo "  revocation-data-plane-container-smoke - Run combined Phase 6.5 smoke in privileged container"
	@echo "  ipsec-xfrm-preflight - Check root/netns/XFRM/StrongSwan prerequisites"
	@echo "  ipsec-xfrm-smoke - Run real StrongSwan/XFRM smoke (requires root, NOT in smoke-all)"
	@echo "  ipsec-xfrm-container-smoke - Run StrongSwan/XFRM smoke in privileged container"
	@echo "  bird-babel-preflight - Check root/netns/BIRD prerequisites"
	@echo "  bird-babel-smoke - Run real BIRD/Babel smoke (requires root, NOT in smoke-all)"
	@echo "  phase7-1-bird-experiment - Run the explicit Phase 7.1 dual-interface BIRD experiment (requires root)"
	@echo "  phase7-1-wg-gre-experiment - Run explicit Phase 7.1 shared-WG/GRE and staged-rotate experiments (requires root)"
	@echo "  bird-babel-container-smoke - Run BIRD/Babel smoke in privileged container"
	@echo "  observer-smoke - Run Phase 6.7 web observer API + SSE + static UI smoke test"
	@echo "  help    - Show this help message"
