package text

import "text/tabwriter"

// Each diagnostic section has its own widths so a long error or identity does
// not widen unrelated tables. Escape runtime text before it reaches tabwriter.
func writeDebugTable(out *lineWriter, rows [][]string) {
	if out.err != nil {
		return
	}
	table := tabwriter.NewWriter(out.w, 0, 4, 2, ' ', 0)
	section := newLineWriter(table)
	for _, row := range rows {
		for i := range row {
			row[i] = escapeTableCell(row[i])
		}
	}
	writeAlignedRows(section, rows)
	if out.err = section.Err(); out.err == nil {
		out.err = table.Flush()
	}
}
