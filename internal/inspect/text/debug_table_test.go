package text

import (
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/HiggsNet/photon/internal/inspect"
)

func TestDebugTableEscapesRuntimeText(t *testing.T) {
	var buf strings.Builder
	out := newLineWriter(&buf)
	writeDebugTable(out, [][]string{{"FIELD", "VALUE"}, {"error", "peer\tfailed\nretry\rnow"}})
	if err := out.Err(); err != nil {
		t.Fatal(err)
	}
	if strings.Count(buf.String(), "\n") != 2 || !strings.Contains(buf.String(), `peer\tfailed\nretry\rnow`) {
		t.Fatalf("runtime text broke table rows: %q", buf.String())
	}
}

type failingDebugWriter struct{}

func (failingDebugWriter) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }

func TestDebugTablesPropagateWriteFailure(t *testing.T) {
	for name, render := range map[string]func(io.Writer) error{
		"links": func(w io.Writer) error {
			return WriteLinksDebug(w, inspect.LinksDebugView{Inspection: inspect.LinkInspection{Links: []inspect.LinkView{{ID: "link"}}}})
		},
		"rotate": func(w io.Writer) error {
			return WriteRotateDebug(w, inspect.RotateDebugView{Links: []inspect.RotateDebugLink{{Link: inspect.LinkView{ID: "link"}}}})
		},
		"peers": func(w io.Writer) error {
			return WritePeerLifecycleDebug(w, inspect.PeerLifecycleDebugView{Peers: []inspect.PeerStatusInfo{{PeerID: "peer"}}})
		},
	} {
		t.Run(name, func(t *testing.T) {
			if err := render(failingDebugWriter{}); !errors.Is(err, io.ErrClosedPipe) {
				t.Fatalf("write error = %v", err)
			}
		})
	}
}
