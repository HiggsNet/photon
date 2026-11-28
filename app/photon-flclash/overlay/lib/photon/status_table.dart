import 'package:fl_clash/common/common.dart';
import 'package:fl_clash/ui/icons/icons.dart';
import 'package:fl_clash/widgets/widgets.dart';
import 'package:flutter/widgets.dart';

class PhotonTableRow {
  const PhotonTableRow({
    required this.title,
    required this.cells,
    this.id,
    this.details = const [],
    this.detailSections = const [],
    this.onPressed,
    this.expanded,
  });

  final String title;
  final Object? id;
  final List<Widget> cells;
  final List<(String, String)> details;
  final List<({String title, List<(String, String)> lines})> detailSections;
  final VoidCallback? onPressed;
  final Widget? expanded;
}

class PhotonTable extends StatelessWidget {
  const PhotonTable({
    super.key,
    required this.columns,
    required this.length,
    required this.rowAt,
    this.wideColumn,
    this.detailsTitle,
    this.truncated = false,
  });

  final List<TableColumn> columns;
  final int length;
  final PhotonTableRow Function(BuildContext, int) rowAt;
  final TableColumn? wideColumn;
  final String? detailsTitle;
  final bool truncated;

  @override
  Widget build(BuildContext context) {
    final l = context.appLocalizations;
    return SliverLayoutBuilder(
      builder: (context, constraints) {
        final width = constraints.crossAxisExtent;
        final scale = MediaQuery.textScalerOf(context);
        final showWide = wideColumn != null && width >= scale.scale(780);
        final headers = [
          ...columns,
          if (showWide) wideColumn!,
          if (detailsTitle != null) const TableColumn('details', '', width: 30),
        ];
        final widths = tableColumnWidths(headers, width);
        final colors = context.colorScheme;
        final stripe = SurfaceLevel.block.colorOf(colors);
        Widget cells(List<Widget> content, {bool header = false}) =>
            DefaultTextStyle.merge(
              style: AppTextStyle.caption1.of(context, emphasized: header),
              maxLines: 1,
              overflow: TextOverflow.ellipsis,
              child: TableCells(
                columns: headers,
                widths: widths,
                height: scale.scale(header ? 32 : 36),
                inset: 6,
                cells: content,
              ),
            );

        return SliverMainAxisGroup(
          slivers: [
            if (truncated) SliverToBoxAdapter(child: Text(l.photonTruncated)),
            SliverToBoxAdapter(
              child: DecoratedBox(
                decoration: ShapeDecoration(
                  color: stripe,
                  shape: AppShape.top(AppCorner.md),
                ),
                child: cells([
                  for (final column in headers)
                    Semantics(
                      header: true,
                      child: Tooltip(
                        message: column.label,
                        child: Text(column.label),
                      ),
                    ),
                ], header: true),
              ),
            ),
            if (length == 0)
              SliverToBoxAdapter(
                child: Padding(
                  padding: const EdgeInsets.symmetric(vertical: 16),
                  child: Text(l.photonEmpty, textAlign: TextAlign.center),
                ),
              ),
            SliverPrismList(
              itemCount: length,
              itemBuilder: (context, index) {
                final row = rowAt(context, index);
                final fill = index.isEven
                    ? SurfaceLevel.card.colorOf(colors)
                    : stripe;
                final title = detailsTitle;
                final content = cells([
                  ...row.cells.take(columns.length + (showWide ? 1 : 0)),
                  if (title != null)
                    GlyphIcon(
                      row.onPressed == null
                          ? AppGlyphs.chevronForward
                          : row.expanded == null
                          ? AppGlyphs.chevronDown
                          : AppGlyphs.chevronUp,
                      size: 14,
                    ),
                ]);
                if (title == null) {
                  return ColoredBox(color: fill, child: content);
                }
                final button = PressSurface(
                  key: ValueKey(row.id ?? row.title),
                  fill: fill,
                  shape: AppShape.none,
                  onPressed:
                      row.onPressed ??
                      () => showSheet<void>(
                        context: context,
                        builder: (context) => Scaffold(
                          title: row.title,
                          body: SingleChildScrollView(
                            padding: EdgeInsets.fromLTRB(
                              16,
                              context.sectionsTopPadding,
                              16,
                              16,
                            ),
                            child: Column(
                              crossAxisAlignment: CrossAxisAlignment.stretch,
                              spacing: 16,
                              children: [
                                if (row.detailSections.isEmpty)
                                  PhotonDetailCard(
                                    title: title,
                                    lines: row.details,
                                  ),
                                for (final section in row.detailSections)
                                  PhotonDetailCard(
                                    title: section.title,
                                    lines: section.lines,
                                  ),
                              ],
                            ),
                          ),
                        ),
                      ),
                  child: content,
                );
                if (row.onPressed == null) return button;
                return Column(
                  crossAxisAlignment: CrossAxisAlignment.stretch,
                  children: [
                    Semantics(expanded: row.expanded != null, child: button),
                    if (row.expanded case final expanded?)
                      ColoredBox(color: fill, child: expanded),
                  ],
                );
              },
            ),
          ],
        );
      },
    );
  }
}

Widget photonStatusMark(String label, Object? value) => Tooltip(
  message: label,
  child: value == true
      ? const GlyphIcon(AppGlyphs.check, size: 14)
      : Text(value == false ? '—' : '?'),
);

class PhotonDetailCard extends StatelessWidget {
  const PhotonDetailCard({
    super.key,
    required this.title,
    required this.lines,
    this.footer,
  });

  final String title;
  final List<(String, String)> lines;
  final Widget? footer;

  @override
  Widget build(BuildContext context) => Card(
    child: Padding(
      padding: const EdgeInsets.all(20),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        spacing: 12,
        children: [
          Text(
            title,
            style: AppTextStyle.headline.of(context, emphasized: true),
          ),
          for (final (label, value) in lines)
            if (value.isNotEmpty)
              Row(
                crossAxisAlignment: CrossAxisAlignment.start,
                spacing: 16,
                children: [
                  SizedBox(
                    width: 132,
                    child: Text(
                      label,
                      style: AppTextStyle.subheadline.of(context),
                    ),
                  ),
                  Expanded(
                    child: SelectableText(
                      value,
                      style: AppTextStyle.body.of(context),
                    ),
                  ),
                ],
              ),
          ?footer,
        ],
      ),
    ),
  );
}

int comparePhotonNodeNames(String a, String b) {
  final aLabels = a.split('.').reversed.toList();
  final bLabels = b.split('.').reversed.toList();
  for (var i = 0; i < aLabels.length && i < bLabels.length; i++) {
    final aParts = aLabels[i].split('-').reversed.toList();
    final bParts = bLabels[i].split('-').reversed.toList();
    for (var j = 0; j < aParts.length && j < bParts.length; j++) {
      final order = bParts[j].compareTo(aParts[j]);
      if (order != 0) return order;
    }
    final order = bParts.length.compareTo(aParts.length);
    if (order != 0) return order;
  }
  return bLabels.length.compareTo(aLabels.length);
}
