// Package capture 提供 WinDivert 句柄封装与抓包主循环。
package capture

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"time"

	"tls-mitm/internal/config"
	"tls-mitm/internal/mutate"
	"tls-mitm/internal/reassembly"
	"tls-mitm/internal/session"
	"tls-mitm/internal/tcpmeta"
	"tls-mitm/internal/tlshello"
)

type packetHandle interface {
	Recv() ([]byte, any, error)
	Send(packet []byte, addr any) error
	Close() error
}

type blockerFactory func(key session.Key) (packetHandle, error)

type recvKind uint8

const (
	recvKindOutboundObserve recvKind = iota
	recvKindOutboundBlock
	recvKindInboundObserve
)

type recvEvent struct {
	kind   recvKind
	key    session.Key
	packet []byte
	addr   any
	err    error
}

// BuildFilters 根据配置构造出站和入站方向的 WinDivert 过滤表达式。
func BuildFilters(cfg config.Config) (string, string) {
	if cfg.TargetIP.IsValid() {
		return fmt.Sprintf("(outbound and tcp and ip and ip.DstAddr == %s and tcp.DstPort == %d)", cfg.TargetIP, cfg.TargetPort),
			fmt.Sprintf("(inbound and tcp and ip and ip.SrcAddr == %s and tcp.SrcPort == %d)", cfg.TargetIP, cfg.TargetPort)
	}

	return fmt.Sprintf("(outbound and tcp and ip and tcp.DstPort == %d)", cfg.TargetPort),
		fmt.Sprintf("(inbound and tcp and ip and tcp.SrcPort == %d)", cfg.TargetPort)
}

// BuildOutboundConnectionFilter 为单条已命中的连接构造专用出站阻断过滤表达式。
func BuildOutboundConnectionFilter(key session.Key) string {
	return fmt.Sprintf(
		"(outbound and tcp and ip and ip.SrcAddr == %s and tcp.SrcPort == %d and ip.DstAddr == %s and tcp.DstPort == %d)",
		key.ClientIP,
		key.ClientPort,
		key.ServerIP,
		key.ServerPort,
	)
}

// RunLoop 运行抓包、篡改、重注入与结果观察主循环。
func RunLoop(ctx context.Context, cfg config.Config, logger *slog.Logger, outHandle, inHandle packetHandle) error {
	return runLoopWithHandles(ctx, cfg, logger, nil, outHandle, inHandle, nil)
}

func runLoopWithHandles(
	ctx context.Context,
	cfg config.Config,
	logger *slog.Logger,
	outObserveHandle, outBlockHandle, inHandle packetHandle,
	newBlockHandle blockerFactory,
) error {
	logger = ensureLogger(logger)

	loopCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	store := session.NewStore(time.Now)
	reported := make(map[session.Key]struct{})
	events := make(chan recvEvent, 4)
	deadlines := make(map[session.Key]time.Time)
	blockers := make(map[session.Key]packetHandle)

	var (
		wg        sync.WaitGroup
		closeOnce sync.Once
		timer     *time.Timer
		timerC    <-chan time.Time
	)
	closeHandles := func() {
		closeOnce.Do(func() {
			if outObserveHandle != nil {
				_ = outObserveHandle.Close()
			}
			if outBlockHandle != nil {
				_ = outBlockHandle.Close()
			}
			if inHandle != nil {
				_ = inHandle.Close()
			}
			for _, handle := range blockers {
				_ = handle.Close()
			}
		})
	}
	stopTimer := func() {
		if timer == nil {
			return
		}
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
	}
	resetTimer := func() {
		if len(deadlines) == 0 {
			stopTimer()
			timerC = nil
			return
		}

		var next time.Time
		for _, deadline := range deadlines {
			if next.IsZero() || deadline.Before(next) {
				next = deadline
			}
		}

		// 始终只维护最近一个观察截止时间，避免为每条连接单独起 goroutine。
		wait := time.Until(next)
		if wait < 0 {
			wait = 0
		}

		if timer == nil {
			timer = time.NewTimer(wait)
		} else {
			stopTimer()
			timer.Reset(wait)
		}
		timerC = timer.C
	}
	shutdown := func(err error) error {
		cancel()
		stopTimer()
		closeHandles()
		wg.Wait()
		return err
	}

	closeDynamicBlocker := func(key session.Key) {
		handle, ok := blockers[key]
		if !ok {
			return
		}
		delete(blockers, key)
		_ = handle.Close()
	}

	startReader := func(handle packetHandle, kind recvKind, key session.Key) {
		if handle == nil {
			return
		}

		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				packet, addr, err := handle.Recv()
				select {
				case events <- recvEvent{kind: kind, key: key, packet: packet, addr: addr, err: err}:
				case <-loopCtx.Done():
					return
				}
				if err != nil {
					// 读循环把错误作为最后一个事件交给主循环统一收口，避免 goroutine 自己决定退出语义。
					return
				}
			}
		}()
	}

	readers := 0
	if outObserveHandle != nil {
		readers++
		startReader(outObserveHandle, recvKindOutboundObserve, session.Key{})
	}
	if outBlockHandle != nil {
		readers++
		startReader(outBlockHandle, recvKindOutboundBlock, session.Key{})
	}
	if inHandle != nil {
		readers++
		startReader(inHandle, recvKindInboundObserve, session.Key{})
	}

	for readers > 0 || len(deadlines) > 0 {
		select {
		case <-loopCtx.Done():
			return shutdown(ctx.Err())
		case <-timerC:
			now := time.Now()
			for key, deadline := range deadlines {
				if deadline.After(now) {
					continue
				}
				result := store.Observe(key, session.Signal{})
				logResultOnce(logger, reported, store, key, result, "timeout")
				delete(deadlines, key)
				closeDynamicBlocker(key)
				store.Forget(key)
			}
			resetTimer()
		case event := <-events:
			if event.err != nil {
				if loopCtx.Err() != nil {
					readers--
					continue
				}
				if errors.Is(event.err, io.EOF) {
					readers--
					continue
				}
				if event.kind == recvKindOutboundBlock {
					if _, exists := blockers[event.key]; !exists {
						logger.Debug(
							"忽略已关闭动态阻断句柄返回的预期读错误",
							"client_ip", event.key.ClientIP,
							"client_port", event.key.ClientPort,
							"server_ip", event.key.ServerIP,
							"server_port", event.key.ServerPort,
							"error", event.err,
						)
						readers--
						continue
					}
				}
				return shutdown(event.err)
			}

			switch event.kind {
			case recvKindOutboundObserve:
				key, matched, cleanup, err := processObservedOutbound(cfg, logger, store, event.packet)
				if err != nil {
					return shutdown(err)
				}
				if cleanup {
					delete(deadlines, key)
					closeDynamicBlocker(key)
					resetTimer()
				}
				if matched && newBlockHandle != nil {
					if _, exists := blockers[key]; !exists {
						handle, err := newBlockHandle(key)
						if err != nil {
							return shutdown(err)
						}
						blockers[key] = handle
						readers++
						startReader(handle, recvKindOutboundBlock, key)
					}
				}
				continue
			case recvKindOutboundBlock:
				key, mutated, cleanup, err := processBlockedOutbound(cfg, logger, store, event.key, event.packet, event.addr, eventSender(event.key, outBlockHandle, blockers))
				if err != nil {
					return shutdown(err)
				}
				if cleanup {
					delete(deadlines, key)
					closeDynamicBlocker(key)
					resetTimer()
				}
				if mutated {
					// 只有真正完成过一次篡改的连接才进入观察窗口。
					deadlines[key] = time.Now().Add(cfg.ObserveTimeout)
					resetTimer()
				}
			case recvKindInboundObserve:
				key, result, observed, cleanup, err := processInbound(logger, store, reported, cfg, event.packet)
				if err != nil {
					return shutdown(err)
				}
				if cleanup {
					delete(deadlines, key)
					closeDynamicBlocker(key)
					resetTimer()
				}
				if observed && result.Outcome != session.OutcomeUnknown {
					delete(deadlines, key)
					closeDynamicBlocker(key)
					resetTimer()
				}
			}
		}
	}

	return shutdown(nil)
}

func processObservedOutbound(
	cfg config.Config,
	logger *slog.Logger,
	store *session.Store,
	packet []byte,
) (session.Key, bool, bool, error) {
	meta, err := tcpmeta.ParseIPv4TCP(packet)
	if err != nil {
		logger.Debug("跳过无法解析的出站观察数据包", "error", err)
		return session.Key{}, false, false, nil
	}

	key := outboundKey(meta)
	if !matchesOutbound(cfg, meta) {
		return session.Key{}, false, false, nil
	}

	signal := observeSignal(false, meta)
	matched := false

	if shouldResolveHost(cfg, store, key) {
		if serverName, ok := tlshello.ParseServerName(meta.Payload); ok {
			if hostMatches(cfg, serverName) {
				store.MarkMatched(key)
				matched = true
				logger.Info(
					"SNI 命中目标域名",
					"trace_id", store.TraceID(key),
					"client_ip", key.ClientIP,
					"client_port", key.ClientPort,
					"server_ip", key.ServerIP,
					"server_port", key.ServerPort,
					"target_host", cfg.TargetHost,
					"matched_host", serverName,
				)
			} else {
				store.MarkExcluded(key)
				logger.Info(
					"SNI 未命中目标域名",
					"trace_id", store.TraceID(key),
					"client_ip", key.ClientIP,
					"client_port", key.ClientPort,
					"server_ip", key.ServerIP,
					"server_port", key.ServerPort,
					"target_host", cfg.TargetHost,
					"observed_host", serverName,
				)
			}
		}
	}

	if isTerminalSignal(signal) && !store.HasMutation(key) {
		store.Forget(key)
		return key, matched, true, nil
	}
	return key, matched, false, nil
}

func processBlockedOutbound(
	cfg config.Config,
	logger *slog.Logger,
	store *session.Store,
	knownKey session.Key,
	packet []byte,
	addr any,
	handle packetHandle,
) (session.Key, bool, bool, error) {
	meta, err := tcpmeta.ParseIPv4TCP(packet)
	if err != nil {
		logger.Debug("跳过无法解析的出站数据包", "error", err)
		return session.Key{}, false, false, handle.Send(packet, addr)
	}

	key := outboundKey(meta)
	if knownKey != (session.Key{}) {
		key = knownKey
	}
	if !matchesOutbound(cfg, meta) {
		return session.Key{}, false, false, handle.Send(packet, addr)
	}

	signal := observeSignal(false, meta)

	if handle == nil {
		logger.Debug(
			"跳过已失效阻断句柄的迟到出站事件",
			"client_ip", key.ClientIP,
			"client_port", key.ClientPort,
			"server_ip", key.ServerIP,
			"server_port", key.ServerPort,
			"seq", meta.Seq,
			"payload_len", len(meta.Payload),
		)
		if isTerminalSignal(signal) && !store.HasMutation(key) {
			store.Forget(key)
			return key, false, true, nil
		}
		return key, false, false, nil
	}

	if cfg.TargetHost == "" {
		store.MarkMatched(key)
	} else if shouldResolveHost(cfg, store, key) {
		if serverName, ok := tlshello.ParseServerName(meta.Payload); ok {
			if hostMatches(cfg, serverName) {
				store.MarkMatched(key)
				logger.Info(
					"SNI 命中目标域名",
					"trace_id", store.TraceID(key),
					"client_ip", key.ClientIP,
					"client_port", key.ClientPort,
					"server_ip", key.ServerIP,
					"server_port", key.ServerPort,
					"target_host", cfg.TargetHost,
					"matched_host", serverName,
				)
			} else {
				store.MarkExcluded(key)
				logger.Info(
					"SNI 未命中目标域名",
					"trace_id", store.TraceID(key),
					"client_ip", key.ClientIP,
					"client_port", key.ClientPort,
					"server_ip", key.ServerIP,
					"server_port", key.ServerPort,
					"target_host", cfg.TargetHost,
					"observed_host", serverName,
				)
			}
		}
	}

	if !isConnectionMatched(cfg, store, key) {
		if err := handle.Send(packet, addr); err != nil {
			return session.Key{}, false, false, err
		}
		if isTerminalSignal(signal) && !store.HasMutation(key) {
			store.Forget(key)
			return key, false, true, nil
		}
		return session.Key{}, false, false, nil
	}

	originalPayload := append([]byte(nil), meta.Payload...)
	packetMutated := false
	var firstAppliedMutation *mutate.AppliedMutation
	recordMutation := func(applied mutate.AppliedMutation) {
		if firstAppliedMutation == nil {
			appliedCopy := applied
			firstAppliedMutation = &appliedCopy
		}
		packetMutated = true
	}
	refreshObservationWindow := func() error {
		if !packetMutated {
			return nil
		}
		if firstAppliedMutation == nil {
			return fmt.Errorf("篡改出站 TLS 密文失败: 未找到已应用的篡改点")
		}

		byteIndex := meta.PayloadOffset + firstAppliedMutation.PayloadIndex
		enteredObservation := store.TryMarkMutated(key, cfg.ObserveTimeout, byteIndex)
		logger.Info(
			"命中完整 application data 破坏点",
			"trace_id", store.TraceID(key),
			"client_ip", key.ClientIP,
			"client_port", key.ClientPort,
			"server_ip", key.ServerIP,
			"server_port", key.ServerPort,
			"payload_index", firstAppliedMutation.PayloadIndex,
			"packet_index", byteIndex,
			"old_byte", fmt.Sprintf("%02x", firstAppliedMutation.OldByte),
			"new_byte", fmt.Sprintf("%02x", firstAppliedMutation.NewByte),
			"first_observation", enteredObservation,
		)
		return nil
	}

	pendingPoints := store.PendingMutationPoints(key)
	for _, point := range pendingPoints {
		if applied, ok := mutate.ApplyMutationPoint(meta.Payload, meta.Seq, point); ok {
			recordMutation(applied)
		}
	}
	payloadAfterPendingMutations := append([]byte(nil), meta.Payload...)

	state := store.Reassembly(key, meta.Seq)
	points, err := state.Push(reassembly.Segment{
		Seq:  meta.Seq,
		Data: originalPayload,
	}, cfg.MutateOffset)
	if err != nil {
		if errors.Is(err, reassembly.ErrBufferLimitExceeded) {
			copy(meta.Payload, payloadAfterPendingMutations)

			if err := refreshObservationWindow(); err != nil {
				return session.Key{}, false, false, err
			}

			logger.Debug(
				"出站最小重组触发保守放行",
				"client_ip", key.ClientIP,
				"client_port", key.ClientPort,
				"server_ip", key.ServerIP,
				"server_port", key.ServerPort,
				"seq", meta.Seq,
				"payload_len", len(meta.Payload),
				"error", err,
			)

			if err := handle.Send(packet, addr); err != nil {
				return session.Key{}, false, false, err
			}
			if isTerminalSignal(signal) && !store.HasMutation(key) {
				store.Forget(key)
				return key, false, true, nil
			}
			return key, packetMutated, false, nil
		}
		return session.Key{}, false, false, err
	}
	for _, point := range points {
		store.AddMutationPoint(key, point)
		if applied, ok := mutate.ApplyMutationPoint(meta.Payload, meta.Seq, point); ok {
			recordMutation(applied)
		}
	}

	if cfg.TargetHost != "" && !packetMutated && (len(pendingPoints) > 0 || payloadStartsApplicationData(meta.Payload)) {
		logger.Debug(
			"目标连接已命中，但当前包尚未覆盖破坏点",
			"trace_id", store.TraceID(key),
			"client_ip", key.ClientIP,
			"client_port", key.ClientPort,
			"server_ip", key.ServerIP,
			"server_port", key.ServerPort,
			"target_host", cfg.TargetHost,
			"seq", meta.Seq,
			"payload_len", len(meta.Payload),
			"pending_points", len(pendingPoints),
		)
	}

	if err := refreshObservationWindow(); err != nil {
		return session.Key{}, false, false, err
	}

	// 未命中可篡改 record 时仍然需要原样放行数据包，保证实验工具只在命中时修改流量。
	if err := handle.Send(packet, addr); err != nil {
		return session.Key{}, false, false, err
	}
	if isTerminalSignal(signal) && !store.HasMutation(key) {
		store.Forget(key)
		return key, false, true, nil
	}
	return key, packetMutated, false, nil
}

func processOutbound(
	cfg config.Config,
	logger *slog.Logger,
	store *session.Store,
	handle packetHandle,
	packet []byte,
	addr any,
) (session.Key, bool, bool, error) {
	return processBlockedOutbound(cfg, logger, store, session.Key{}, packet, addr, handle)
}

func eventSender(key session.Key, static packetHandle, blockers map[session.Key]packetHandle) packetHandle {
	if key != (session.Key{}) {
		if handle, ok := blockers[key]; ok {
			return handle
		}
	}
	return static
}

func processInbound(
	logger *slog.Logger,
	store *session.Store,
	reported map[session.Key]struct{},
	cfg config.Config,
	packet []byte,
) (session.Key, session.Result, bool, bool, error) {
	meta, err := tcpmeta.ParseIPv4TCP(packet)
	if err != nil {
		logger.Debug("跳过无法解析的入站数据包", "error", err)
		return session.Key{}, session.Result{}, false, false, nil
	}
	if !matchesInbound(cfg, meta) {
		return session.Key{}, session.Result{}, false, false, nil
	}

	key := inboundKey(meta)
	store.AckUpTo(key, meta.Ack)
	signal := observeSignal(true, meta)
	if !store.HasMutation(key) {
		if isTerminalSignal(signal) {
			store.Forget(key)
			return key, session.Result{}, true, true, nil
		}
		return key, session.Result{}, false, false, nil
	}

	result := store.Observe(key, signal)
	logResultOnce(logger, reported, store, key, result, signalReason(signal))
	cleanup := isTerminalSignal(signal) || result.Outcome != session.OutcomeUnknown
	if cleanup {
		store.Forget(key)
	}
	return key, result, true, cleanup, nil
}

func ensureLogger(logger *slog.Logger) *slog.Logger {
	if logger != nil {
		return logger
	}
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func matchesOutbound(cfg config.Config, meta tcpmeta.Packet) bool {
	return matchesPortAndOptionalIP(cfg, meta, true)
}

func matchesInbound(cfg config.Config, meta tcpmeta.Packet) bool {
	return matchesPortAndOptionalIP(cfg, meta, false)
}

func matchesPortAndOptionalIP(cfg config.Config, meta tcpmeta.Packet, outbound bool) bool {
	if cfg.TargetIP.IsValid() {
		if outbound {
			return meta.DstIP == cfg.TargetIP && meta.DstPort == cfg.TargetPort
		}
		return meta.SrcIP == cfg.TargetIP && meta.SrcPort == cfg.TargetPort
	}

	if outbound {
		return meta.DstPort == cfg.TargetPort
	}
	return meta.SrcPort == cfg.TargetPort
}

func shouldResolveHost(cfg config.Config, store *session.Store, key session.Key) bool {
	if cfg.TargetHost == "" {
		return false
	}
	return store.MatchState(key) == session.MatchStateUnknown
}

func hostMatches(cfg config.Config, name string) bool {
	return cfg.TargetHost != "" && name == cfg.TargetHost
}

func isConnectionMatched(cfg config.Config, store *session.Store, key session.Key) bool {
	if cfg.TargetHost == "" {
		return true
	}
	return store.MatchState(key) == session.MatchStateMatched
}

func outboundKey(meta tcpmeta.Packet) session.Key {
	return session.Key{
		ClientIP:   meta.SrcIP.String(),
		ClientPort: meta.SrcPort,
		ServerIP:   meta.DstIP.String(),
		ServerPort: meta.DstPort,
	}
}

func inboundKey(meta tcpmeta.Packet) session.Key {
	return session.Key{
		ClientIP:   meta.DstIP.String(),
		ClientPort: meta.DstPort,
		ServerIP:   meta.SrcIP.String(),
		ServerPort: meta.SrcPort,
	}
}

func observeSignal(fromServer bool, meta tcpmeta.Packet) session.Signal {
	return session.Signal{
		FromServer: fromServer,
		RST:        meta.TCPFlags&0x04 != 0,
		FIN:        meta.TCPFlags&0x01 != 0,
		Alert:      looksLikeTLSAlert(meta.Payload),
	}
}

func signalReason(sig session.Signal) string {
	switch {
	case sig.RST:
		return "rst"
	case sig.FIN:
		return "fin"
	case sig.Alert:
		return "alert"
	default:
		return "observe"
	}
}

func isTerminalSignal(sig session.Signal) bool {
	return sig.FIN || sig.RST
}

func logResultOnce(
	logger *slog.Logger,
	reported map[session.Key]struct{},
	store *session.Store,
	key session.Key,
	result session.Result,
	reason string,
) {
	if result.Outcome == session.OutcomeUnknown {
		return
	}
	if result.Outcome == session.OutcomeNoConclusion && reason != "timeout" {
		return
	}
	if _, ok := reported[key]; ok {
		return
	}
	reported[key] = struct{}{}

	logger.Info(
		"连接观察结果",
		"trace_id", store.TraceID(key),
		"client_ip", key.ClientIP,
		"client_port", key.ClientPort,
		"server_ip", key.ServerIP,
		"server_port", key.ServerPort,
		"outcome", string(result.Outcome),
		"observed_for", result.ObservedFor.String(),
		"byte_index", result.ByteIndex,
		"reason", reason,
	)
}

func looksLikeTLSAlert(payload []byte) bool {
	record, ok := findCompleteTLSRecord(payload)
	return ok && record.contentType == 0x15
}

func payloadStartsApplicationData(payload []byte) bool {
	if len(payload) < 5 {
		return false
	}
	version := uint16(payload[1])<<8 | uint16(payload[2])
	return payload[0] == 0x17 && isTLSVersion(version)
}

type tlsPacketRecord struct {
	contentType byte
}

func findCompleteTLSRecord(payload []byte) (tlsPacketRecord, bool) {
	const headerLen = 5

	for offset := 0; offset+headerLen <= len(payload); {
		contentType := payload[offset]
		version := uint16(payload[offset+1])<<8 | uint16(payload[offset+2])
		if !isTLSContentType(contentType) || !isTLSVersion(version) {
			offset++
			continue
		}

		dataLen := int(payload[offset+3])<<8 | int(payload[offset+4])
		totalLen := headerLen + dataLen
		if offset+totalLen > len(payload) {
			offset++
			continue
		}

		return tlsPacketRecord{contentType: contentType}, true
	}

	return tlsPacketRecord{}, false
}

func isTLSContentType(contentType byte) bool {
	return contentType >= 20 && contentType <= 24
}

func isTLSVersion(version uint16) bool {
	return version >= 0x0300 && version <= 0x0304
}
