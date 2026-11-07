package mihomoproxy

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/HiggsNet/photon/internal/photonwindows"
)

const requestTimeout = 2 * time.Second

// Core owns one Mihomo child and its temporary state. It does not configure
// system proxy settings or TUN. The API credential stays inside the manager.
type Core struct {
	mu      sync.Mutex
	run     *coreRun
	lastErr error
}

type coreRun struct {
	child       *exec.Cmd
	done        chan struct{}
	waitErr     error
	home        string
	template    Template
	listener    Listener
	api         *http.Client
	profile     []byte
	photonPaths []string
	expires     time.Time
	expiry      *time.Timer
}

type Group struct {
	Name     string   `json:"name"`
	Type     string   `json:"type"`
	Selected string   `json:"now"`
	Choices  []string `json:"all"`
	Hidden   bool     `json:"hidden"`
}

type Status struct {
	Running      bool
	PhotonOnline bool
	Port         uint16
	Groups       []Group
}

func (c *Core) Start(ctx context.Context, executable string, port uint16, template Template) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.run != nil && c.run.running() {
		return errors.New("Mihomo is already running")
	}
	if err := c.stopLocked(); err != nil {
		return err
	}
	if !filepath.IsAbs(executable) || port == 0 {
		return errors.New("Mihomo requires an absolute executable path and a local proxy port")
	}
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return err
	}
	apiPort, err := localPort(port)
	if err != nil {
		return err
	}
	listener := Listener{MixedPort: port, ControllerPort: apiPort, Secret: hex.EncodeToString(secret)}
	profile, _, err := template.Render(listener, nil, time.Now())
	if err != nil {
		return err
	}
	home, err := os.MkdirTemp("", "photon-mihomo-")
	if err != nil {
		return err
	}
	r := &coreRun{
		home: home, template: template, listener: listener, profile: profile,
		api: &http.Client{
			Timeout:       requestTimeout,
			Transport:     &http.Transport{DisableKeepAlives: true},
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}
	// Only publish the owned process after it has proved that both listeners
	// are active. A listening controller alone does not prove the proxy port.
	if err := r.start(ctx, executable); err != nil {
		return errors.Join(err, r.stop())
	}
	c.run, c.lastErr = r, nil
	return nil
}

func localPort(mixedPort uint16) (uint16, error) {
	mixed, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(mixedPort)})
	if err != nil {
		return 0, fmt.Errorf("local proxy port is unavailable: %w", err)
	}
	defer mixed.Close()
	api, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return 0, err
	}
	defer api.Close()
	return uint16(api.Addr().(*net.TCPAddr).Port), nil
}

func (r *coreRun) start(ctx context.Context, executable string) error {
	path := filepath.Join(r.home, "config.yaml")
	if err := os.WriteFile(path, r.profile, 0600); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()
	check := exec.CommandContext(ctx, executable, "-d", r.home, "-f", path, "-t")
	configureCommand(check)
	if output, err := check.CombinedOutput(); err != nil {
		detail := strings.ReplaceAll(strings.TrimSpace(string(output)), r.listener.Secret, "[redacted]")
		if len(detail) > 4096 {
			detail = detail[len(detail)-4096:]
		}
		return fmt.Errorf("Mihomo config check: %w: %s", err, detail)
	}
	cmd := exec.Command(executable, "-d", r.home, "-f", path)
	configureCommand(cmd)
	if err := cmd.Start(); err != nil {
		return err
	}
	r.child, r.done = cmd, make(chan struct{})
	release, err := ownProcess(cmd)
	go func() {
		r.waitErr = cmd.Wait()
		if release != nil {
			release()
		}
		close(r.done)
	}()
	if err != nil {
		return err
	}
	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()
	for {
		var current struct {
			MixedPort uint16 `json:"mixed-port"`
		}
		if err := r.request(ctx, http.MethodGet, "/configs", nil, &current); err == nil {
			if current.MixedPort != r.listener.MixedPort {
				return errors.New("Mihomo did not acquire the local proxy port")
			}
			return nil
		}
		select {
		case <-r.done:
			return fmt.Errorf("Mihomo exited during startup: %v", r.waitErr)
		case <-ctx.Done():
			return fmt.Errorf("Mihomo controller did not become ready: %w", ctx.Err())
		case <-tick.C:
		}
	}
}

func (c *Core) Stop() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.lastErr = nil
	return c.stopLocked()
}

func (c *Core) stopLocked() error {
	if c.run == nil {
		return nil
	}
	if err := c.run.stop(); err != nil {
		return err
	}
	c.run = nil
	return nil
}

func (r *coreRun) stop() error {
	if r.expiry != nil {
		r.expiry.Stop()
	}
	if r.running() {
		err := r.child.Process.Kill()
		if err != nil && !errors.Is(err, os.ErrProcessDone) {
			return fmt.Errorf("stop owned Mihomo process: %w", err)
		}
		<-r.done
	}
	return os.RemoveAll(r.home)
}

func (r *coreRun) running() bool {
	if r.child == nil {
		return false
	}
	select {
	case <-r.done:
		return false
	default:
		return true
	}
}

func (c *Core) Status(ctx context.Context) (Status, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	r := c.run
	if r == nil {
		return Status{}, c.lastErr
	}
	if !r.running() {
		return Status{}, fmt.Errorf("Mihomo exited: %v", r.waitErr)
	}
	status := Status{Running: true, PhotonOnline: time.Now().Before(r.expires), Port: r.listener.MixedPort}
	var response struct {
		Proxies map[string]Group `json:"proxies"`
	}
	if err := r.request(ctx, http.MethodGet, "/proxies", nil, &response); err != nil {
		return status, err
	}
	for _, group := range response.Proxies {
		if len(group.Choices) > 0 && !group.Hidden {
			status.Groups = append(status.Groups, group)
		}
	}
	slices.SortFunc(status.Groups, func(a, b Group) int { return strings.Compare(a.Name, b.Name) })
	return status, nil
}

func (c *Core) Select(ctx context.Context, group, choice string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.run == nil || !c.run.running() {
		return errors.New("Mihomo is not running")
	}
	return c.run.request(ctx, http.MethodPut, "/proxies/"+url.PathEscape(group), map[string]string{"name": choice}, nil)
}

// Sync updates the directory from the verified Photon backend. Invalid or
// missing observations retire Photon routes while ordinary user routes remain.
func (c *Core) Sync(ctx context.Context, directory *photonwindows.ServiceDirectory) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.run == nil {
		return nil
	}
	if !c.run.running() {
		return fmt.Errorf("Mihomo exited: %v", c.run.waitErr)
	}
	return c.syncLocked(ctx, directory)
}

func (c *Core) syncLocked(ctx context.Context, directory *photonwindows.ServiceDirectory) error {
	r := c.run
	now := time.Now()
	profile, online, invalid := r.template.Render(r.listener, directory, now)
	if invalid != nil {
		var err error
		profile, online, err = r.template.Render(r.listener, nil, now)
		if err != nil {
			c.lastErr = errors.Join(invalid, err, c.stopLocked())
			return c.lastErr
		}
	}
	if !bytes.Equal(r.profile, profile) {
		if err := r.reload(ctx, profile); err != nil {
			// A stale policy may still route through a withdrawn endpoint.
			c.lastErr = errors.Join(invalid, err, c.stopLocked())
			return c.lastErr
		}
		r.profile = profile
	}
	if r.expiry != nil {
		r.expiry.Stop()
	}
	r.expires = time.Time{}
	if online {
		// The renderer already validated the snapshot at now.
		endpoints, _, _ := directoryConfig(directory, now)
		r.photonPaths = slices.Clone(photonGroups)
		for _, endpoint := range endpoints {
			r.photonPaths = append(r.photonPaths, endpoint["name"].(string))
		}
		r.expires = directory.ValidUntil
		expires := r.expires
		r.expiry = time.AfterFunc(time.Until(expires), func() {
			c.mu.Lock()
			defer c.mu.Unlock()
			if c.run == r && r.expires == expires {
				ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
				defer cancel()
				_ = c.syncLocked(ctx, nil)
			}
		})
	} else {
		r.photonPaths = nil
	}
	return invalid
}

func (r *coreRun) reload(ctx context.Context, profile []byte) error {
	ctx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	if err := r.request(ctx, http.MethodPut, "/configs?force=true", map[string]string{"payload": string(profile)}, nil); err != nil {
		return fmt.Errorf("apply Mihomo config: %w", err)
	}
	if len(r.photonPaths) == 0 {
		return nil
	}
	var snapshot struct {
		Connections []struct {
			ID     string   `json:"id"`
			Chains []string `json:"chains"`
		} `json:"connections"`
	}
	if err := r.request(ctx, http.MethodGet, "/connections", nil, &snapshot); err != nil {
		return err
	}
	for _, conn := range snapshot.Connections {
		if slices.ContainsFunc(conn.Chains, func(name string) bool { return slices.Contains(r.photonPaths, name) }) {
			if err := r.request(ctx, http.MethodDelete, "/connections/"+url.PathEscape(conn.ID), nil, nil); err != nil {
				return err
			}
		}
	}
	return nil
}

func (r *coreRun) request(ctx context.Context, method, path string, body any, result any) error {
	var payload []byte
	if body != nil {
		var err error
		payload, err = json.Marshal(body)
		if err != nil {
			return err
		}
	}
	endpoint := fmt.Sprintf("http://127.0.0.1:%d%s", r.listener.ControllerPort, path)
	req, err := http.NewRequestWithContext(ctx, method, endpoint, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+r.listener.Secret)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	response, err := r.api.Do(req)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("Mihomo %s %s returned HTTP %d", method, path, response.StatusCode)
	}
	if result == nil {
		return nil
	}
	return json.NewDecoder(io.LimitReader(response.Body, 8<<20)).Decode(result)
}
