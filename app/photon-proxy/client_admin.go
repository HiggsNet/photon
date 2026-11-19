package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

func serveClientAdmin(ctx context.Context, listener net.Listener, manager *routeManager) error {
	server := &http.Server{
		Handler:           routeAdminHandler(manager),
		ReadHeaderTimeout: 3 * time.Second,
		ReadTimeout:       setupTimeout,
		WriteTimeout:      setupTimeout,
		IdleTimeout:       time.Minute,
		MaxHeaderBytes:    8 << 10,
	}
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	select {
	case <-ctx.Done():
		_ = server.Close()
		<-done
		return nil
	case err := <-manager.errors:
		_ = server.Close()
		<-done
		return err
	case err := <-done:
		_ = server.Close()
		return err
	}
}

func listenClientAdmin(path string) (net.Listener, error) {
	parent := filepath.Dir(path)
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return nil, err
	}
	info, err := os.Stat(parent)
	if err != nil {
		return nil, err
	}
	if info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("admin_socket needs a private parent directory, such as one with mode 0700")
	}
	if err := removeStaleAdminSocket(path); err != nil {
		return nil, err
	}
	listener, err := net.Listen("unix", path)
	if err != nil {
		return nil, fmt.Errorf("listen on admin_socket: %w", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		_ = listener.Close()
		return nil, err
	}
	return listener, nil
}

func removeStaleAdminSocket(path string) error {
	old, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if old.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("admin_socket path %s is not a socket", path)
	}
	conn, err := net.DialTimeout("unix", path, time.Second)
	if err == nil {
		_ = conn.Close()
		return fmt.Errorf("admin_socket %s is already listening", path)
	}
	if !errors.Is(err, syscall.ECONNREFUSED) {
		return fmt.Errorf("check admin_socket: %w", err)
	}
	current, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !os.SameFile(old, current) {
		return fmt.Errorf("admin_socket %s changed during startup", path)
	}
	return os.Remove(path)
}

func routeAdminHandler(manager *routeManager) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/routes", func(w http.ResponseWriter, _ *http.Request) {
		writeRouteJSON(w, http.StatusOK, manager.list())
	})
	mux.HandleFunc("POST /v1/routes", func(w http.ResponseWriter, r *http.Request) {
		var request routeInfo
		if !readRouteJSON(w, r, &request) {
			return
		}
		info, err := manager.create(request.Name, request.clientRoute)
		if err != nil {
			writeRouteError(w, err)
			return
		}
		writeRouteJSON(w, http.StatusCreated, info)
	})
	mux.HandleFunc("PUT /v1/routes/{name}", func(w http.ResponseWriter, r *http.Request) {
		var request clientRoute
		if !readRouteJSON(w, r, &request) {
			return
		}
		info, err := manager.replace(r.PathValue("name"), request)
		if err != nil {
			writeRouteError(w, err)
			return
		}
		writeRouteJSON(w, http.StatusOK, info)
	})
	mux.HandleFunc("DELETE /v1/routes/{name}", func(w http.ResponseWriter, r *http.Request) {
		if err := manager.remove(r.PathValue("name")); err != nil {
			writeRouteError(w, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	return mux
}

func readRouteJSON(w http.ResponseWriter, r *http.Request, destination any) bool {
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 32<<10))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		writeRouteError(w, fmt.Errorf("%w: %w", errRouteInvalid, err))
		return false
	}
	if err := decoder.Decode(new(json.RawMessage)); err != io.EOF {
		writeRouteError(w, fmt.Errorf("%w: expected one JSON object", errRouteInvalid))
		return false
	}
	return true
}

func writeRouteError(w http.ResponseWriter, err error) {
	status := http.StatusInternalServerError
	switch {
	case errors.Is(err, errRouteInvalid):
		status = http.StatusBadRequest
	case errors.Is(err, errRouteConflict):
		status = http.StatusConflict
	case errors.Is(err, errRouteNotFound):
		status = http.StatusNotFound
	case errors.Is(err, context.Canceled):
		status = http.StatusServiceUnavailable
	}
	writeRouteJSON(w, status, map[string]string{"error": err.Error()})
}

func writeRouteJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}
