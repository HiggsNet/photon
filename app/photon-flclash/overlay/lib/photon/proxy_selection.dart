/// User choices apply to generated Photon exits, independently of user templates.
/// Exclusions keep newly discovered regions/nodes enabled and remember withdrawals.
final class PhotonProxySelection {
  PhotonProxySelection({
    Set<String> protocols = const {'socks5'},
    Set<String> excludedRegions = const {},
    Set<String> excludedNodes = const {},
  }) : protocols = Set.unmodifiable(protocols),
       excludedRegions = Set.unmodifiable(excludedRegions),
       excludedNodes = Set.unmodifiable(excludedNodes);

  factory PhotonProxySelection.fromJson(Map<String, dynamic> json) =>
      PhotonProxySelection(
        protocols: Set<String>.from(json['protocols'] as List),
        excludedRegions: Set<String>.from(json['excluded_regions'] as List),
        excludedNodes: Set<String>.from(json['excluded_nodes'] as List),
      );

  final Set<String> protocols;
  final Set<String> excludedRegions;
  final Set<String> excludedNodes;

  bool allows({
    required String type,
    required String region,
    required String owner,
  }) =>
      protocols.contains(type) &&
      !excludedRegions.contains(region) &&
      (region != 'local' || !excludedNodes.contains(owner));

  Map<String, dynamic> toJson() => {
    'protocols': protocols.toList()..sort(),
    'excluded_regions': excludedRegions.toList()..sort(),
    'excluded_nodes': excludedNodes.toList()..sort(),
  };
}
