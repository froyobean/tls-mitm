//go:build windows

package capture

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"time"

	divert "github.com/imgk/divert-go"
	"golang.org/x/sys/windows"

	"tls-mitm/internal/config"
	"tls-mitm/internal/mutate"
	"tls-mitm/internal/reassembly"
	"tls-mitm/internal/session"
	"tls-mitm/internal/tcpmeta"
	"tls-mitm/internal/tlshello"
)

// Handle 封装一份 WinDivert 句柄及其关闭逻辑。
type Handle struct {
	h         *divert.Handle
	closeOnce sync.Once
}

type hostOnlyLifecycle uint8

const (
	hostOnlyLifecycleNone hostOnlyLifecycle = iota
	hostOnlyLifecycleRoundEnd
	hostOnlyLifecycleConnectionEnd
)

type hostOnlyConnectionState struct {
	clientFINSeen bool
	serverFINSeen bool
}

type hostOnlyEventResult struct {
	key             session.Key
	matched         bool
	observed        bool
	mutated         bool
	signal          session.Signal
	result          session.Result
	resultDirection string
}

func advanceHostOnlyLifecycle(state *hostOnlyConnectionState, signal session.Signal, result session.Result) hostOnlyLifecycle {
	if state == nil {
		state = &hostOnlyConnectionState{}
	}

	if signal.RST {
		return hostOnlyLifecycleConnectionEnd
	}
	if signal.FIN {
		if signal.FromServer {
			if state.clientFINSeen {
				return hostOnlyLifecycleConnectionEnd
			}
			state.serverFINSeen = true
		} else {
			if state.serverFINSeen {
				return hostOnlyLifecycleConnectionEnd
			}
			state.clientFINSeen = true
		}
	}
	if hasKnownOutcome(result) {
		return hostOnlyLifecycleRoundEnd
	}
	return hostOnlyLifecycleNone
}

func hasKnownOutcome(result session.Result) bool {
	return result.Outcome != "" && result.Outcome != session.OutcomeUnknown
}

func hostOnlyHalfCloseTimeout(cfg config.Config) time.Duration {
	timeout := cfg.ObserveTimeout * 5
	if timeout <= 0 {
		return time.Second
	}
	return timeout
}

// OpenHandle 打开用于阻断和重注入的 WinDivert 句柄。
func OpenHandle(filter string) (*Handle, error) {
	return openHandle(filter, divert.PriorityDefault, divert.FlagDefault)
}

// OpenObserveHandle 打开仅用于观察数据的 WinDivert 句柄。
func OpenObserveHandle(filter string) (*Handle, error) {
	return openHandle(filter, divert.PriorityDefault, divert.FlagSniff)
}

// OpenHandleWithPriority 打开一个指定优先级的阻断/重注入句柄。
func OpenHandleWithPriority(filter string, priority int16) (*Handle, error) {
	return openHandle(filter, priority, divert.FlagDefault)
}

// OpenObserveHandleWithPriority 打开一个指定优先级的观察句柄。
func OpenObserveHandleWithPriority(filter string, priority int16) (*Handle, error) {
	return openHandle(filter, priority, divert.FlagSniff)
}

// BuildInboundConnectionFilter 为单条已命中的连接构造专用入站阻断过滤表达式。
func BuildInboundConnectionFilter(key session.Key) string {
	return fmt.Sprintf(
		"(inbound and tcp and ip and ip.SrcAddr == %s and tcp.SrcPort == %d and ip.DstAddr == %s and tcp.DstPort == %d)",
		key.ServerIP,
		key.ServerPort,
		key.ClientIP,
		key.ClientPort,
	)
}

// BuildBidirectionalConnectionFilter 为单条已命中的连接构造双向阻断过滤表达式。
func BuildBidirectionalConnectionFilter(key session.Key) string {
	return fmt.Sprintf(
		"((outbound and tcp and ip and ip.SrcAddr == %s and tcp.SrcPort == %d and ip.DstAddr == %s and tcp.DstPort == %d) or (inbound and tcp and ip and ip.SrcAddr == %s and tcp.SrcPort == %d and ip.DstAddr == %s and tcp.DstPort == %d))",
		key.ClientIP,
		key.ClientPort,
		key.ServerIP,
		key.ServerPort,
		key.ServerIP,
		key.ServerPort,
		key.ClientIP,
		key.ClientPort,
	)
}

// RunHostMatchLoop 运行基于 SNI 命中的“先观察、后阻断”主循环。
func RunHostMatchLoop(
	ctx context.Context,
	cfg config.Config,
	logger *slog.Logger,
	outObserveHandle, inObserveHandle *Handle,
	newBlockHandle func(key session.Key) (*Handle, error),
) error {
	var factory blockerFactory
	if newBlockHandle != nil {
		factory = func(key session.Key) (packetHandle, error) {
			return newBlockHandle(key)
		}
	}
	return runHostMatchLoopWithHandles(ctx, cfg, logger, outObserveHandle, inObserveHandle, factory)
}

func runHostMatchLoopWithHandles(
	ctx context.Context,
	cfg config.Config,
	logger *slog.Logger,
	outObserveHandle, inObserveHandle packetHandle,
	newBlockHandle blockerFactory,
) error {
	logger = ensureLogger(logger)

	loopCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	store := session.NewStore(time.Now)
	reported := make(map[session.Key]struct{})
	events := make(chan recvEvent, 8)
	deadlines := make(map[session.Key]time.Time)
	halfCloseDeadlines := make(map[session.Key]time.Time)
	blockers := make(map[session.Key]packetHandle)
	blockerKinds := make(map[session.Key]recvKind)
	observeDirections := make(map[session.Key]string)
	connectionStates := make(map[session.Key]hostOnlyConnectionState)

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
			if inObserveHandle != nil {
				_ = inObserveHandle.Close()
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
		if len(deadlines) == 0 && len(halfCloseDeadlines) == 0 {
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
		for _, deadline := range halfCloseDeadlines {
			if next.IsZero() || deadline.Before(next) {
				next = deadline
			}
		}

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
	directionFor := func(key session.Key) string {
		if direction, ok := observeDirections[key]; ok && direction != "" {
			return direction
		}
		return mutationDirectionOut
	}
	lifecycleFor := func(result hostOnlyEventResult) hostOnlyLifecycle {
		if result.key == (session.Key{}) {
			return hostOnlyLifecycleNone
		}
		state := connectionStates[result.key]
		lifecycle := advanceHostOnlyLifecycle(&state, result.signal, result.result)
		connectionStates[result.key] = state
		return lifecycle
	}
	isHalfClosed := func(key session.Key) bool {
		state := connectionStates[key]
		return state.clientFINSeen != state.serverFINSeen
	}
	closeDynamicBlocker := func(key session.Key) {
		handle, ok := blockers[key]
		if !ok {
			return
		}
		delete(blockers, key)
		delete(blockerKinds, key)
		_ = handle.Close()
	}
	resetObservationCycle := func(key session.Key) {
		delete(deadlines, key)
		delete(observeDirections, key)
		delete(reported, key)
		store.ResetObservation(key)
	}
	retainConnection := func(key session.Key) {
		resetObservationCycle(key)
	}
	retainHalfClosedConnection := func(key session.Key) {
		resetObservationCycle(key)
		halfCloseDeadlines[key] = time.Now().Add(hostOnlyHalfCloseTimeout(cfg))
	}
	touchHalfClose := func(key session.Key) {
		if key == (session.Key{}) || !isHalfClosed(key) {
			return
		}
		halfCloseDeadlines[key] = time.Now().Add(hostOnlyHalfCloseTimeout(cfg))
		resetTimer()
	}
	startObservationCycle := func(key session.Key, direction string) {
		delete(halfCloseDeadlines, key)
		observeDirections[key] = direction
		deadlines[key] = time.Now().Add(cfg.ObserveTimeout)
		resetTimer()
	}
	cleanupConnection := func(key session.Key) {
		resetObservationCycle(key)
		delete(halfCloseDeadlines, key)
		closeDynamicBlocker(key)
		delete(connectionStates, key)
		store.Forget(key)
	}
	applyEventResult := func(result hostOnlyEventResult) {
		if result.key == (session.Key{}) {
			return
		}
		if result.observed && hasKnownOutcome(result.result) {
			logResultOnce(logger, reported, store, result.key, result.result, signalReason(result.signal), result.resultDirection)
		}

		switch lifecycleFor(result) {
		case hostOnlyLifecycleRoundEnd:
			if isHalfClosed(result.key) {
				retainHalfClosedConnection(result.key)
			} else {
				retainConnection(result.key)
			}
			resetTimer()
		case hostOnlyLifecycleConnectionEnd:
			cleanupConnection(result.key)
			resetTimer()
		default:
			if result.signal.FIN && isHalfClosed(result.key) {
				retainHalfClosedConnection(result.key)
				resetTimer()
			}
		}
	}
	shutdown := func(err error) error {
		cancel()
		stopTimer()
		closeHandles()
		wg.Wait()
		return err
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
					return
				}
			}
		}()
	}
	observeCfg := cfg
	observeCfg.MutateDirection = "out"
	blockKind := hostMatchBlockRecvKind(cfg)

	readers := 0
	if outObserveHandle != nil {
		readers++
		startReader(outObserveHandle, recvKindOutboundObserve, session.Key{})
	}
	if inObserveHandle != nil {
		readers++
		startReader(inObserveHandle, recvKindInboundObserve, session.Key{})
	}

	for readers > 0 || len(deadlines) > 0 || len(halfCloseDeadlines) > 0 {
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
				logResultOnce(logger, reported, store, key, result, "timeout", directionFor(key))
				if hasKnownOutcome(result) {
					if isHalfClosed(key) {
						retainHalfClosedConnection(key)
					} else {
						retainConnection(key)
					}
				} else {
					cleanupConnection(key)
				}
			}
			for key, deadline := range halfCloseDeadlines {
				if deadline.After(now) {
					continue
				}
				cleanupConnection(key)
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
				if isDynamicHostBlockKind(event.kind) {
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
				result, err := processHostOnlyObservedOutbound(cfg, logger, store, event.packet)
				if err != nil {
					return shutdown(err)
				}
				touchHalfClose(result.key)
				applyEventResult(result)
				if result.matched && newBlockHandle != nil {
					if _, exists := blockers[result.key]; !exists {
						handle, err := newBlockHandle(result.key)
						if err != nil {
							return shutdown(err)
						}
						blockers[result.key] = handle
						blockerKinds[result.key] = blockKind
						readers++
						startReader(handle, blockKind, result.key)
					}
				}
			case recvKindInboundObserve:
				meta, err := tcpmeta.ParseIPv4TCP(event.packet)
				if err == nil && matchesInbound(cfg, meta) {
					key := inboundKey(meta)
					if kind, ok := blockerKinds[key]; ok && (kind == recvKindInboundBlock || kind == recvKindBidirectionalBlock) {
						continue
					}
				}

				resultDirection := mutationDirectionOut
				if err == nil && matchesInbound(cfg, meta) {
					resultDirection = directionFor(inboundKey(meta))
				}

				result, err := processHostOnlyInbound(logger, store, observeCfg, event.packet, event.addr, nil, resultDirection)
				if err != nil {
					return shutdown(err)
				}
				touchHalfClose(result.key)
				applyEventResult(result)
			case recvKindOutboundBlock:
				resultDirection := directionFor(event.key)
				result, err := processHostOnlyBlockedOutbound(cfg, logger, store, event.key, event.packet, event.addr, blockers[event.key], resultDirection)
				if err != nil {
					return shutdown(err)
				}
				touchHalfClose(result.key)
				if result.mutated {
					startObservationCycle(result.key, mutationDirectionOut)
				}
				applyEventResult(result)
			case recvKindInboundBlock:
				resultDirection := directionFor(event.key)
				result, err := processHostOnlyInbound(logger, store, cfg, event.packet, event.addr, blockers[event.key], resultDirection)
				if err != nil {
					return shutdown(err)
				}
				touchHalfClose(result.key)
				if result.mutated {
					startObservationCycle(result.key, mutationDirectionIn)
				}
				applyEventResult(result)
			case recvKindBidirectionalBlock:
				handle := blockers[event.key]
				if handle == nil {
					continue
				}

				meta, err := tcpmeta.ParseIPv4TCP(event.packet)
				if err != nil {
					if sendErr := handle.Send(event.packet, event.addr); sendErr != nil {
						return shutdown(sendErr)
					}
					continue
				}

				switch {
				case matchesOutbound(cfg, meta):
					resultDirection := directionFor(event.key)
					result, err := processHostOnlyBlockedOutbound(cfg, logger, store, event.key, event.packet, event.addr, handle, resultDirection)
					if err != nil {
						return shutdown(err)
					}
					touchHalfClose(result.key)
					if result.mutated {
						startObservationCycle(result.key, mutationDirectionOut)
					}
					applyEventResult(result)
				case matchesInbound(cfg, meta):
					resultDirection := directionFor(event.key)
					result, err := processHostOnlyInbound(logger, store, cfg, event.packet, event.addr, handle, resultDirection)
					if err != nil {
						return shutdown(err)
					}
					touchHalfClose(result.key)
					if result.mutated {
						startObservationCycle(result.key, mutationDirectionIn)
					}
					applyEventResult(result)
				default:
					if err := handle.Send(event.packet, event.addr); err != nil {
						return shutdown(err)
					}
				}
			}
		}
	}

	return shutdown(nil)
}

func processHostOnlyObservedOutbound(
	cfg config.Config,
	logger *slog.Logger,
	store *session.Store,
	packet []byte,
) (hostOnlyEventResult, error) {
	meta, err := tcpmeta.ParseIPv4TCP(packet)
	if err != nil {
		logger.Debug("跳过无法解析的出站观察数据包", "error", err)
		return hostOnlyEventResult{}, nil
	}

	key := outboundKey(meta)
	if !matchesOutbound(cfg, meta) {
		return hostOnlyEventResult{}, nil
	}

	store.AckInboundUpTo(key, meta.Ack)
	result := hostOnlyEventResult{
		key:             key,
		signal:          observeSignal(false, meta),
		resultDirection: mutationDirectionOut,
	}

	if shouldResolveHost(cfg, store, key) {
		if serverName, ok := tlshello.ParseServerName(meta.Payload); ok {
			if hostMatches(cfg, serverName) {
				store.MarkMatched(key)
				result.matched = true
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

	return result, nil
}

func processHostOnlyBlockedOutbound(
	cfg config.Config,
	logger *slog.Logger,
	store *session.Store,
	knownKey session.Key,
	packet []byte,
	addr any,
	handle packetHandle,
	resultDirection string,
) (hostOnlyEventResult, error) {
	meta, err := tcpmeta.ParseIPv4TCP(packet)
	if err != nil {
		logger.Debug("跳过无法解析的出站数据包", "error", err)
		if handle == nil {
			return hostOnlyEventResult{}, nil
		}
		return hostOnlyEventResult{}, handle.Send(packet, addr)
	}

	key := outboundKey(meta)
	if knownKey != (session.Key{}) {
		key = knownKey
	}
	result := hostOnlyEventResult{
		key:             key,
		signal:          observeSignal(false, meta),
		resultDirection: resultDirection,
	}

	if !matchesOutbound(cfg, meta) {
		if handle == nil {
			return result, nil
		}
		return result, handle.Send(packet, addr)
	}

	store.AckInboundUpTo(key, meta.Ack)

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
		return result, nil
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
		return result, handle.Send(packet, addr)
	}

	originalPayload := append([]byte(nil), meta.Payload...)
	var firstAppliedMutation *mutate.AppliedMutation
	recordMutation := func(applied mutate.AppliedMutation) {
		if firstAppliedMutation == nil {
			appliedCopy := applied
			firstAppliedMutation = &appliedCopy
		}
		result.mutated = true
	}
	refreshObservationWindow := func() error {
		if !result.mutated {
			return nil
		}
		if firstAppliedMutation == nil {
			return fmt.Errorf("篡改出站 TLS 密文失败: 未找到已应用的篡改点")
		}

		byteIndex := meta.PayloadOffset + firstAppliedMutation.PayloadIndex
		enteredObservation := store.TryMarkMutated(key, cfg.ObserveTimeout, byteIndex)
		logger.Info(
			"命中完整 application data 破坏点",
			"direction", mutationDirectionOut,
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

	if mutatesOutbound(cfg) {
		pendingPoints := store.OutboundPendingMutationPoints(key)
		for _, point := range pendingPoints {
			if applied, ok := mutate.ApplyMutationPoint(meta.Payload, meta.Seq, point); ok {
				recordMutation(applied)
			}
		}
		payloadAfterPendingMutations := append([]byte(nil), meta.Payload...)

		state := store.OutboundReassembly(key, meta.Seq)
		points, err := state.Push(reassembly.Segment{
			Seq:  meta.Seq,
			Data: originalPayload,
		}, cfg.MutateOffset)
		if err != nil {
			if errors.Is(err, reassembly.ErrBufferLimitExceeded) {
				copy(meta.Payload, payloadAfterPendingMutations)

				if err := refreshObservationWindow(); err != nil {
					return hostOnlyEventResult{}, err
				}

				logger.Debug(
					"出站最小重组触发保守放行",
					"direction", mutationDirectionOut,
					"client_ip", key.ClientIP,
					"client_port", key.ClientPort,
					"server_ip", key.ServerIP,
					"server_port", key.ServerPort,
					"seq", meta.Seq,
					"payload_len", len(meta.Payload),
					"error", err,
				)

				if err := handle.Send(packet, addr); err != nil {
					return hostOnlyEventResult{}, err
				}
				if isTerminalSignal(result.signal) && store.HasMutation(key) {
					result.result = store.Observe(key, result.signal)
					result.observed = true
				}
				return result, nil
			}
			return hostOnlyEventResult{}, err
		}
		for _, point := range points {
			store.AddOutboundMutationPoint(key, point)
			if applied, ok := mutate.ApplyMutationPoint(meta.Payload, meta.Seq, point); ok {
				recordMutation(applied)
			}
		}

		if cfg.TargetHost != "" && !result.mutated && (len(pendingPoints) > 0 || payloadStartsApplicationData(meta.Payload)) {
			logger.Debug(
				"目标连接已命中，但当前包尚未覆盖破坏点",
				"direction", mutationDirectionOut,
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
			return hostOnlyEventResult{}, err
		}
	}

	if err := handle.Send(packet, addr); err != nil {
		return hostOnlyEventResult{}, err
	}
	if isTerminalSignal(result.signal) && store.HasMutation(key) {
		result.result = store.Observe(key, result.signal)
		result.observed = true
	}
	return result, nil
}

func processHostOnlyInbound(
	logger *slog.Logger,
	store *session.Store,
	cfg config.Config,
	packet []byte,
	addr any,
	handle packetHandle,
	resultDirection string,
) (hostOnlyEventResult, error) {
	meta, err := tcpmeta.ParseIPv4TCP(packet)
	if err != nil {
		logger.Debug("跳过无法解析的入站数据包", "error", err)
		return hostOnlyEventResult{}, nil
	}
	if !matchesInbound(cfg, meta) {
		return hostOnlyEventResult{}, nil
	}

	key := inboundKey(meta)
	result := hostOnlyEventResult{
		key:             key,
		signal:          observeSignal(true, meta),
		resultDirection: resultDirection,
	}

	store.AckOutboundUpTo(key, meta.Ack)
	if !isConnectionMatched(cfg, store, key) {
		if handle != nil {
			if err := handle.Send(packet, addr); err != nil {
				return hostOnlyEventResult{}, err
			}
		}
		return result, nil
	}

	if !mutatesInbound(cfg) {
		if handle != nil {
			if err := handle.Send(packet, addr); err != nil {
				return hostOnlyEventResult{}, err
			}
		}
		if !store.HasMutation(key) {
			return result, nil
		}

		result.result = store.Observe(key, result.signal)
		result.observed = true
		return result, nil
	}

	originalPayload := append([]byte(nil), meta.Payload...)
	var firstAppliedMutation *mutate.AppliedMutation
	recordMutation := func(applied mutate.AppliedMutation) {
		if firstAppliedMutation == nil {
			appliedCopy := applied
			firstAppliedMutation = &appliedCopy
		}
		result.mutated = true
	}
	refreshObservationWindow := func() error {
		if !result.mutated {
			return nil
		}
		if firstAppliedMutation == nil {
			return fmt.Errorf("篡改入站 TLS 密文失败: 未找到已应用的篡改点")
		}

		byteIndex := meta.PayloadOffset + firstAppliedMutation.PayloadIndex
		enteredObservation := store.TryMarkMutated(key, cfg.ObserveTimeout, byteIndex)
		logger.Info(
			"命中完整 application data 破坏点",
			"direction", mutationDirectionIn,
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

	pendingPoints := store.InboundPendingMutationPoints(key)
	for _, point := range pendingPoints {
		if applied, ok := mutate.ApplyMutationPoint(meta.Payload, meta.Seq, point); ok {
			recordMutation(applied)
		}
	}
	payloadAfterPendingMutations := append([]byte(nil), meta.Payload...)

	state := store.InboundReassembly(key, meta.Seq)
	points, err := state.Push(reassembly.Segment{
		Seq:  meta.Seq,
		Data: originalPayload,
	}, cfg.MutateOffset)
	if err != nil {
		if errors.Is(err, reassembly.ErrBufferLimitExceeded) {
			copy(meta.Payload, payloadAfterPendingMutations)

			if err := refreshObservationWindow(); err != nil {
				return hostOnlyEventResult{}, err
			}

			logger.Debug(
				"入站最小重组触发保守放行",
				"direction", mutationDirectionIn,
				"client_ip", key.ClientIP,
				"client_port", key.ClientPort,
				"server_ip", key.ServerIP,
				"server_port", key.ServerPort,
				"seq", meta.Seq,
				"payload_len", len(meta.Payload),
				"error", err,
			)

			if handle != nil {
				if err := handle.Send(packet, addr); err != nil {
					return hostOnlyEventResult{}, err
				}
			}
			return result, nil
		}
		return hostOnlyEventResult{}, err
	}
	for _, point := range points {
		store.AddInboundMutationPoint(key, point)
		if applied, ok := mutate.ApplyMutationPoint(meta.Payload, meta.Seq, point); ok {
			recordMutation(applied)
		}
	}

	if cfg.TargetHost != "" && !result.mutated && (len(pendingPoints) > 0 || payloadStartsApplicationData(meta.Payload)) {
		logger.Debug(
			"目标连接已命中，但当前包尚未覆盖破坏点",
			"direction", mutationDirectionIn,
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
		return hostOnlyEventResult{}, err
	}

	if handle != nil {
		if err := handle.Send(packet, addr); err != nil {
			return hostOnlyEventResult{}, err
		}
	}

	if !store.HasMutation(key) {
		return result, nil
	}

	if result.mutated {
		result.resultDirection = mutationDirectionIn
	}
	result.result = store.Observe(key, result.signal)
	result.observed = true
	return result, nil
}

func hostMatchBlockRecvKind(cfg config.Config) recvKind {
	switch cfg.MutateDirection {
	case "in":
		return recvKindInboundBlock
	case "both":
		return recvKindBidirectionalBlock
	default:
		return recvKindOutboundBlock
	}
}

func isDynamicHostBlockKind(kind recvKind) bool {
	return kind == recvKindOutboundBlock || kind == recvKindInboundBlock || kind == recvKindBidirectionalBlock
}

func openHandle(filter string, priority int16, flags uint64) (*Handle, error) {
	handle, err := divert.Open(filter, divert.Layer(0), priority, flags)
	if err != nil {
		return nil, normalizeOpenError(err)
	}
	return &Handle{h: handle}, nil
}

// Recv 从 WinDivert 句柄读取一个数据包及其地址信息。
func (h *Handle) Recv() ([]byte, any, error) {
	buf := make([]byte, divert.MTUMax)
	addr := &divert.Address{}
	n, err := h.h.Recv(buf, addr)
	if err != nil {
		return nil, nil, err
	}
	return append([]byte(nil), buf[:n]...), addr, nil
}

// Send 重算校验和后将数据包重新注入网络栈。
func (h *Handle) Send(packet []byte, addr any) error {
	divertAddr, ok := addr.(*divert.Address)
	if !ok {
		return fmt.Errorf("WinDivert 地址类型不匹配: %T", addr)
	}

	divert.CalcChecksums(packet, divertAddr, divert.ChecksumDefault)
	_, err := h.h.Send(packet, divertAddr)
	return err
}

// Close 关闭底层 WinDivert 句柄。
func (h *Handle) Close() error {
	if h == nil || h.h == nil {
		return nil
	}

	var err error
	h.closeOnce.Do(func() {
		err = h.h.Close()
	})
	return err
}

func normalizeOpenError(err error) error {
	if err == nil {
		return nil
	}

	var divertErr divert.Error
	if errors.As(err, &divertErr) {
		// WinDivert 把底层 Windows 错误码直接透传上来，这里补一层更面向操作者的中文诊断。
		switch windows.Errno(divertErr) {
		case windows.ERROR_SERVICE_DISABLED:
			return fmt.Errorf("打开 WinDivert 失败: 当前 WinDivert 驱动服务处于禁用状态。请以管理员身份执行 `sc.exe config WinDivert start= demand` 后重试；如果仍有问题，可先执行 `sc.exe delete WinDivert` 再重新运行程序让驱动自动重建: %w", err)
		case windows.EPT_S_NOT_REGISTERED:
			return fmt.Errorf("打开 WinDivert 失败: Base Filtering Engine (BFE) 服务未启用，请先启用并启动该服务: %w", err)
		case windows.ERROR_FILE_NOT_FOUND:
			return fmt.Errorf("打开 WinDivert 失败: 未找到 WinDivert 驱动文件，请确认 `WinDivert64.sys` 与可执行文件位于同一目录或驱动已正确安装: %w", err)
		case windows.ERROR_ACCESS_DENIED:
			return fmt.Errorf("打开 WinDivert 失败: 当前进程缺少管理员权限，请使用管理员身份运行: %w", err)
		case 0:
			return fmt.Errorf("打开 WinDivert 失败: 收到了空错误码，这通常意味着 WinDivert 驱动服务状态异常或 `divert_cgo` 路径返回了不完整的错误信息，请优先检查 WinDivert 服务状态: %w", err)
		}
	}

	if err.Error() == "The operation completed successfully." {
		// `divert_cgo` 路径偶尔会把失败场景折叠成空错误码，这里把它改写成可排障的信息。
		return fmt.Errorf("打开 WinDivert 失败: 收到了空错误码，这通常意味着 WinDivert 驱动服务状态异常或 `divert_cgo` 路径返回了不完整的错误信息，请优先检查 WinDivert 服务状态: %w", err)
	}

	return err
}
