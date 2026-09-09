package bird

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Client talks to a running BIRD daemon through birdc over a Unix socket.
type Client interface {
	// Status returns a snapshot of BIRD status, protocols, routes,
	// interfaces and neighbors.
	Status(ctx context.Context) (*BirdObservation, error)

	// Configure performs a full "birdc configure" using the file at path.
	Configure(ctx context.Context, path string) error

	// ConfigureSoft performs "birdc configure soft" using the file at path.
	ConfigureSoft(ctx context.Context, path string) error

	// ReloadIn triggers "birdc reload in <proto>".
	ReloadIn(ctx context.Context, proto string) error

	// ReloadOut triggers "birdc reload out <proto>".
	ReloadOut(ctx context.Context, proto string) error

	// Shutdown performs a graceful shutdown ("birdc down" or SIGTERM).
	Shutdown(ctx context.Context) error

	// Raw runs a single birdc command and returns the unparsed response body.
	Raw(ctx context.Context, cmd string) (string, error)
}

type birdcClient struct {
	socketPath  string
	timeout     time.Duration
	routeTables []string
}

// NewClient creates a new birdc client connected to socketPath.
func NewClient(socketPath string, timeout time.Duration) Client {
	return NewClientWithRouteTables(socketPath, timeout, nil)
}

// NewClientWithRouteTables creates a BIRD client that collects routes from
// the supplied internal tables. Without tables, Status retains the historical
// behavior of querying BIRD's default table with "show route all".
func NewClientWithRouteTables(socketPath string, timeout time.Duration, routeTables []string) Client {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	return &birdcClient{
		socketPath:  socketPath,
		timeout:     timeout,
		routeTables: append([]string(nil), routeTables...),
	}
}

// Status returns a snapshot of BIRD status, protocols, routes, interfaces and neighbors.
func (c *birdcClient) Status(ctx context.Context) (*BirdObservation, error) {
	state := &BirdObservation{
		FetchedAt: time.Now(),
	}

	commands := []struct {
		name  string
		cmd   string
		parse func(string, *BirdObservation)
	}{
		{"status", "show status", func(out string, s *BirdObservation) {
			status, err := parseStatus(out)
			if err != nil {
				s.Warnings = append(s.Warnings, fmt.Sprintf("parse status: %v", err))
				s.Stale = true
				return
			}
			s.Status = status
		}},
		{"protocols", "show protocols all", func(out string, s *BirdObservation) {
			s.Protocols = parseProtocols(out)
		}},
		{"interfaces", "show interfaces", func(out string, s *BirdObservation) {
			s.Interfaces = parseInterfaces(out)
		}},
		{"neighbors", "show babel neighbors", func(out string, s *BirdObservation) {
			s.Neighbors = parseBabelNeighbors(out)
		}},
	}

	for _, item := range commands {
		out, err := c.command(ctx, item.cmd)
		if err != nil {
			state.Warnings = append(state.Warnings, fmt.Sprintf("%s command failed: %v", item.name, err))
			state.Stale = true
			continue
		}
		item.parse(out, state)
	}
	for _, cmd := range c.routeCommands() {
		out, err := c.command(ctx, cmd)
		if err != nil {
			state.Warnings = append(state.Warnings, fmt.Sprintf("routes command %q failed: %v", cmd, err))
			state.Stale = true
			continue
		}
		state.Routes = append(state.Routes, parseRoutes(out)...)
	}

	return state, nil
}

func (c *birdcClient) routeCommands() []string {
	if len(c.routeTables) == 0 {
		return []string{"show route all"}
	}
	commands := make([]string, 0, len(c.routeTables))
	for _, table := range c.routeTables {
		if table != "" {
			commands = append(commands, fmt.Sprintf("show route table %s all", table))
		}
	}
	return commands
}

// Configure performs a full "birdc configure" using the file at path.
// BIRD's CLI requires a configuration filename to be a quoted string.
func (c *birdcClient) Configure(ctx context.Context, path string) error {
	return c.commandCheck(ctx, fmt.Sprintf("configure %q", path))
}

// ConfigureSoft performs "birdc configure soft" using the file at path.
// BIRD's CLI requires a configuration filename to be a quoted string.
func (c *birdcClient) ConfigureSoft(ctx context.Context, path string) error {
	return c.commandCheck(ctx, fmt.Sprintf("configure soft %q", path))
}

// ReloadIn triggers "birdc reload in <proto>".
func (c *birdcClient) ReloadIn(ctx context.Context, proto string) error {
	return c.commandCheck(ctx, fmt.Sprintf("reload in %s", proto))
}

// ReloadOut triggers "birdc reload out <proto>".
func (c *birdcClient) ReloadOut(ctx context.Context, proto string) error {
	return c.commandCheck(ctx, fmt.Sprintf("reload out %s", proto))
}

// Shutdown performs a graceful shutdown ("birdc down" or SIGTERM).
func (c *birdcClient) Shutdown(ctx context.Context) error {
	return c.commandCheck(ctx, "down")
}

// Raw runs a single birdc command and returns the unparsed response body.
func (c *birdcClient) Raw(ctx context.Context, cmd string) (string, error) {
	return c.command(ctx, cmd)
}

// commandCheck runs a command and returns an error if BIRD reports a failure.
func (c *birdcClient) commandCheck(ctx context.Context, cmd string) error {
	out, err := c.command(ctx, cmd)
	if err != nil {
		return err
	}
	if isErrorResponse(out) {
		return fmt.Errorf("birdc error: %s", summarizeError(out))
	}
	return nil
}

// command sends a single birdc command and returns the cleaned response body.
func (c *birdcClient) command(ctx context.Context, cmd string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}

	dialer := net.Dialer{Timeout: c.timeout}
	conn, err := dialer.DialContext(ctx, "unix", c.socketPath)
	if err != nil {
		return "", fmt.Errorf("dial %s: %w", c.socketPath, err)
	}
	defer conn.Close()

	deadline := time.Now().Add(c.timeout)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	_ = conn.SetDeadline(deadline)

	// BIRD sends a greeting before accepting commands. Validate it so a
	// mistakenly configured Unix socket is reported at the actual boundary.
	reader := bufio.NewReader(conn)
	greeting, err := reader.ReadString('\n')
	if err != nil {
		return "", fmt.Errorf("read greeting: %w", err)
	}
	if !strings.HasPrefix(greeting, "0001 BIRD ") {
		return "", fmt.Errorf("unexpected BIRD greeting: %q", strings.TrimSpace(greeting))
	}

	if _, err := fmt.Fprintf(conn, "%s\n", cmd); err != nil {
		return "", fmt.Errorf("write command: %w", err)
	}

	body, err := readResponse(reader)
	if err != nil {
		return body, fmt.Errorf("read response: %w", err)
	}
	return body, nil
}

func readResponse(reader io.Reader) (string, error) {
	var data []byte
	buf := make([]byte, 4096)
	for {
		n, err := reader.Read(buf)
		if n > 0 {
			data = append(data, buf[:n]...)
			if body, ok := completeResponse(data); ok {
				return body, nil
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return string(data), nil
			}
			return string(data), err
		}
	}
}

func completeResponse(data []byte) (string, bool) {
	for start := 0; start < len(data); {
		lineEnd := -1
		for i := start; i < len(data); i++ {
			if data[i] == '\n' {
				lineEnd = i + 1
				break
			}
		}

		if len(data)-start >= 4 && isReplyCode(data[start:start+4]) {
			code := string(data[start : start+4])
			if len(data)-start == 4 {
				if code == "0000" {
					return string(data[:start]), true
				}
				return "", false
			}
			switch data[start+4] {
			case ' ':
				if code == "0000" {
					return string(data[:start]), true
				}
				if lineEnd >= 0 {
					return string(data[:lineEnd]), true
				}
				return "", false
			case '-':
				// Continuation line; keep scanning following complete lines.
			}
		}

		if lineEnd < 0 {
			return "", false
		}
		start = lineEnd
	}
	return "", false
}

func isReplyCode(b []byte) bool {
	if len(b) != 4 {
		return false
	}
	for _, c := range b {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// isErrorResponse reports whether a response body contains an error code line.
func isErrorResponse(output string) bool {
	return errorCodeRe.MatchString(output)
}

var errorCodeRe = regexp.MustCompile(`(?m)^[89]\d{3}[- ]`)

// summarizeError extracts the first error-looking line from a response.
func summarizeError(output string) string {
	for line := range strings.SplitSeq(output, "\n") {
		line = strings.TrimSpace(line)
		if len(line) >= 4 {
			code := line[:4]
			if n, _ := strconv.Atoi(code); n >= 8000 && n <= 9999 {
				return strings.TrimSpace(line[4:])
			}
		}
	}
	return output
}
