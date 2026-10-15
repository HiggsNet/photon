package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/HiggsNet/photon/internal/photonwindows"
	"github.com/HiggsNet/photon/pkg/core/gossip"
)

const desktopLogMaxBytes = 256 << 10
const desktopLogMaxLines = 1000

type desktopLogTail struct {
	Path, Text         string
	Missing, Truncated bool
}

// LogTail reads only the current log, without following links or opening state.
// A started run retains its path after Stop, until a new run replaces it.
func (b *desktopBackend) LogTail() (desktopLogTail, error) {
	b.mu.Lock()
	statePath := ""
	if b.run != nil {
		statePath = b.run.statePath
	}
	b.mu.Unlock()
	if statePath == "" {
		data, _, err := desktopReadConfig(b.options.ConfigPath)
		if errors.Is(err, os.ErrNotExist) {
			statePath = defaultDesktopConfigForm(b.options.ConfigPath).StatePath
		} else if err != nil {
			return desktopLogTail{}, fmt.Errorf("locate runtime log: %w", err)
		} else {
			config, err := desktopParseConfig(string(data))
			if err != nil {
				return desktopLogTail{}, fmt.Errorf("locate runtime log: %w", err)
			}
			statePath = config.State.Path
		}
	}
	out := desktopLogTail{Path: statePath + ".log"}
	file, err := desktopOpenConfig(out.Path) // Windows shares delete access for rotation.
	if errors.Is(err, os.ErrNotExist) {
		out.Missing = true
		return out, nil
	}
	if err != nil {
		return out, fmt.Errorf("read runtime log: %w", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return out, fmt.Errorf("stat runtime log: %w", err)
	}
	if !info.Mode().IsRegular() {
		return out, errors.New("runtime log must be a regular file, not a link or reparse point")
	}
	start := max(int64(0), info.Size()-desktopLogMaxBytes)
	data := make([]byte, info.Size()-start)
	n, err := file.ReadAt(data, start)
	if err != nil && !errors.Is(err, io.EOF) {
		return out, fmt.Errorf("read runtime log tail: %w", err)
	}
	data = data[:n] // A concurrent truncate/rotation may shorten the opened file.
	out.Truncated = start > 0
	if start > 0 {
		// Drop a partial first record when complete later records exist. For a
		// single oversized line retain its suffix, starting at a UTF-8 boundary.
		if newline := bytes.IndexByte(data, '\n'); newline >= 0 && newline < len(data)-1 {
			data = data[newline+1:]
		} else {
			for len(data) > 0 && !utf8.RuneStart(data[0]) {
				data = data[1:]
			}
		}
	}
	end := len(data)
	if end > 0 && data[end-1] == '\n' {
		end--
	}
	lines := 0
	for i := end - 1; i >= 0; i-- {
		if data[i] == '\n' {
			lines++
			if lines == desktopLogMaxLines {
				data, out.Truncated = data[i+1:], true
				break
			}
		}
	}
	// The logger emits UTF-8; tolerate a concurrent partial final code point.
	// ASCII replacement cannot expand a malformed file beyond the byte budget.
	out.Text = strings.ToValidUTF8(string(data), "?")
	return out, nil
}

func desktopLiveSnapshot(snapshot desktopSnapshot) bool {
	return snapshot.RuntimeState == "running" && snapshot.Error == "" && snapshot.Observation != nil && snapshot.Observation.Running
}

func desktopDiagnosticTime(value time.Time) string {
	if value.IsZero() {
		return "尚无时间记录"
	}
	return value.UTC().Format("2006-01-02 15:04:05 UTC")
}

func desktopFormatPeers(snapshot desktopSnapshot) string {
	if !desktopLiveSnapshot(snapshot) {
		text := "实时 Peer 信息不可用，已清空上次节点数据。"
		if snapshot.Error != "" {
			text += "\r\n原因：" + snapshot.Error
		}
		return text
	}
	observation := snapshot.Observation
	var text strings.Builder
	fmt.Fprintf(&text, "Gossip / Peer\r\n采样时间：%s\r\n节点数量：%d\r\n", desktopDiagnosticTime(observation.ObservedAt), len(observation.Peers))
	for _, peer := range observation.Peers {
		state := "未知状态"
		switch gossip.SyncSessionState(peer.PullState) {
		case "":
			state = "暂无会话状态"
		case gossip.SyncSessionIdle:
			state = "等待同步"
		case gossip.SyncSessionPingSent:
			state = "已发送探测"
		case gossip.SyncSessionSummarySent:
			state = "已发送目录摘要"
		case gossip.SyncSessionCatalogDiffing:
			state = "正在比较目录"
		case gossip.SyncSessionObjectPulling:
			state = "正在拉取对象"
		case gossip.SyncSessionChunkFallback:
			state = "使用分块回退同步"
		case gossip.SyncSessionCompleted:
			state = "本次同步已完成"
		case gossip.SyncSessionFailed:
			state = "同步失败"
		}
		fmt.Fprintf(&text, "\r\n节点：%q\r\n同步状态：%s（pull_state=%q）\r\n更新时间：%s\r\n对象拉取累计：尝试 %d · 成功 %d · 失败 %d\r\n", peer.Peer, state, peer.PullState, desktopDiagnosticTime(peer.UpdatedAt), peer.PullAttempts, peer.PullSuccesses, peer.PullFailures)
	}
	if len(observation.Peers) == 0 {
		text.WriteString("\r\n当前有界样本尚无 Peer 活动记录。\r\n")
	}
	if observation.PeersTruncated {
		text.WriteString("\r\n节点列表已截断，仅显示当前有界样本。\r\n")
	}
	return text.String()
}

func desktopFormatDiagnostics(snapshot desktopSnapshot) string {
	value := struct {
		RuntimeState string                     `json:"runtime_state"`
		Available    bool                       `json:"available"`
		Error        string                     `json:"error,omitempty"`
		Observation  *photonwindows.Observation `json:"observation,omitempty"`
	}{RuntimeState: snapshot.RuntimeState, Available: desktopLiveSnapshot(snapshot), Error: snapshot.Error}
	if value.Available {
		value.Observation = snapshot.Observation
	}
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		value.Available, value.Observation = false, nil
		value.Error = "encode live diagnostics: " + err.Error()
		data, _ = json.MarshalIndent(value, "", "  ")
	}
	return string(data)
}
