package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math"
	"math/big"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	"filippo.io/edwards25519"
	vlc "github.com/adrg/libvlc-go/v3"
	"github.com/fxamacker/cbor/v2"
	"github.com/hashicorp/mdns"
	"github.com/quic-go/quic-go"
	"gopkg.in/yaml.v3"

	"github.com/ValiantChip/goutils/pointer"
	randutil "github.com/ValiantChip/goutils/rand"
	osp "github.com/ValiantChip/osp/open_screen"
	"github.com/ValiantChip/osp/spake2"
)

const SERVICE_NAME = "_openscreen._udp."

type Config struct {
	DisplayName *string `yaml:"display_name, omitempty"`
	ServiceName string  `yaml:"-"`
	ModelName   *string `yaml:"model_name, omitempty"`
	Port        *int    `yaml:"port, omitempty"`
	WaitMs      *int    `yaml:"wait, omitempty"`
	MaxRetries  *int    `yaml:"max_retries, omitempty"`
	FFmpegName  *string `yaml:"ffmpeg, omitempty"`
}

var DEFAULT_CONFIG Config = Config{
	DisplayName: pointer.New("MyOpenScreen"),
	ServiceName: SERVICE_NAME,
	ModelName:   pointer.New("unset"),
	WaitMs:      pointer.New(1000),
	MaxRetries:  pointer.New(15),
	Port:        pointer.New(7000),
}

func main() {
	os.Exit(ReturnWithExitCode())
}

var TokenDictionary = []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")

func ReturnWithExitCode() int {
	logger := NewServerLogger(log.New(os.Stdout, "", log.Ltime))
	config := DEFAULT_CONFIG
	configs := flag.String("c", "./config.yaml", "path to the config file must be in yaml format")
	confle, err := os.Open(*configs)
	if err != nil {
		if *configs != "./config.yaml" {
			logger.Error(fmt.Sprintf("unable to open config file: %s", err.Error()))
			return 1
		}
	} else {
		err = yaml.NewDecoder(confle).Decode(&config)
		if err != nil {
			logger.Error(fmt.Sprintf("unable to decode config file: %s", err.Error()))
			return 1
		}
	}
	defer confle.Close()

	server := new(Server)

	server.ctx = context.Background()

	server.closeChan = make(chan ClosingError)

	server.Config = config

	server.Logger = logger

	server.Capabilities = osp.AuthCapabilities{
		PskEaseOfInput:      50,
		PskInputMethods:     []osp.PskInputMethod{osp.Numeric},
		PskMinBitsOfEntropy: 32,
	}

	err = vlc.Init()
	if err != nil {
		server.Logger.Error(fmt.Sprintf("error initializing vlc: %s", err.Error()))
		return 1
	}
	defer vlc.Release()

	player, err := vlc.NewPlayer()
	if err != nil {
		server.Logger.Error(fmt.Sprintf("error creating vlc player: %s", err.Error()))
		return 1
	}
	server.Player = player
	defer player.Stop()
	defer player.Release()

	at, err := randutil.Bytes(rand.Reader, TokenDictionary, 16)
	if err != nil {
		panic(err)
	}
	server.AuthToken = string(at)

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}

	skpi, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		panic(err)
	}

	s := sha256.Sum256(skpi)

	fp := base64.RawStdEncoding.EncodeToString(s[:])

	server.Fingerprint = fp

	serialBase, err := rand.Int(rand.Reader, big.NewInt(math.MaxInt32))
	if err != nil {
		panic(err)
	}

	serialNumber := osp.GetSerialNumber(serialBase, 0)

	server.SerialNumber = serialNumber

	template := &x509.Certificate{
		Version:            3,
		SerialNumber:       server.SerialNumber,
		Issuer:             pkix.Name{CommonName: *server.Config.ModelName},
		Subject:            pkix.Name{CommonName: server.Fingerprint + SERVICE_NAME},
		SignatureAlgorithm: x509.ECDSAWithSHA256,
		PublicKeyAlgorithm: x509.ECDSA,
		KeyUsage:           x509.KeyUsageDigitalSignature,
		NotAfter:           time.Now().AddDate(1, 0, 0),
		NotBefore:          time.Now(),
	}

	cert, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		panic(err)
	}

	pair := tls.Certificate{
		Certificate: [][]byte{cert},
		PrivateKey:  privateKey,
	}

	tlsConfig := &tls.Config{
		Certificates:       []tls.Certificate{pair},
		NextProtos:         []string{"osp"},
		ServerName:         server.Fingerprint + SERVICE_NAME,
		InsecureSkipVerify: true,
		ClientAuth:         tls.RequireAnyClientCert,
	}

	quicConfig := &quic.Config{
		MaxIdleTimeout:  2 * time.Minute,
		KeepAlivePeriod: time.Second * 10,
	}

	dns, err := MdnsServer(server, logger)

	if err != nil {
		logger.Error(fmt.Sprintf("unable to create mdns server: %s\n", err.Error()))
		return 1
	}

	defer dns.Shutdown()

	udp, err := net.ListenUDP("udp", &net.UDPAddr{Port: *server.Config.Port})
	if err != nil {
		logger.Error(fmt.Sprintf("unable to create udp listener: %s\n", err.Error()))
		return 1
	}

	transport := &quic.Transport{
		Conn:               udp,
		ConnectionIDLength: 6,
	}

	ln, err := transport.Listen(tlsConfig, quicConfig)
	if err != nil {
		logger.Error(fmt.Sprintf("unable to listen to udp: %s", err.Error()))
		return 1
	}

	server.Listener = ln

	server.AcceptConnections()

	return 0
}

type ClosingError struct {
	Err  error
	Code quic.ApplicationErrorCode
}

func (e ClosingError) Error() string {
	return e.Err.Error()
}

type Server struct {
	Config       Config
	Cert         *x509.Certificate
	ctx          context.Context
	Fingerprint  string
	AuthToken    string
	Capabilities osp.AuthCapabilities
	SerialNumber *big.Int
	Listener     *quic.Listener
	closeChan    chan ClosingError
	Logger       *serverLogger
	Player       *vlc.Player
}

func (s *Server) Close(err error, code quic.ApplicationErrorCode) {
	s.Listener.Close()
	s.closeChan <- ClosingError{Err: err, Code: code}
}

var errNoAvailablePlayer = errors.New("player not available")
var errRequestFail = errors.New("request media failed")

func (s *Server) StartPlay(url string, maxRetry int, wait time.Duration) (*vlc.Media, error) {
	if s.Player == nil {
		return nil, errNoAvailablePlayer
	}
	if maxRetry < 1 {
		maxRetry = math.MaxInt
	}
	for range maxRetry {
		s.Logger.Info(fmt.Sprintf("requesting media: %s", url))
		media, err := s.Player.LoadMediaFromURL(url)
		if err != nil {
			s.Logger.Error("request media failed")
			return nil, err
		}

		if s.Player.WillPlay() {
			return media, nil
		}

		s.Logger.Info("request media failed waiting")
		time.Sleep(wait)
	}

	return nil, errRequestFail
}

type ClientInfo struct {
	PlaybackId osp.RemotePlaybackId
}

var defaultTimeout = time.Second * 10

type Agent struct {
	Conn               *quic.Conn
	Server             *Server
	infoMu             sync.RWMutex
	clientInfo         ClientInfo
	capabilitiesMu     sync.RWMutex
	clientCapabilities *osp.AuthCapabilities
	state              osp.RemotePlaybackState
	stateMu            sync.RWMutex
	capabilitiesRecv   chan bool
	MsgHandler         *osp.MessageHandler
}

func (s *Server) NewAgent(conn *quic.Conn) *Agent {
	a := new(Agent)
	a.Conn = conn
	a.Server = s
	a.capabilitiesRecv = make(chan bool)
	a.MsgHandler = osp.NewMessageHandler()
	a.MsgHandler.AddHandler(osp.AuthCapabilitiesKey, func(msg []byte) {
		a.HandleAuthCapabilities(msg)
	})
	a.MsgHandler.AddHandler(osp.StreamingSessionStartRequestKey, func(msg []byte) {
		a.HandleStreamingSessionStartRequest(msg)
	})
	a.MsgHandler.AddHandler(osp.StreamingCapabilitiesRequestKey, func(msg []byte) {
		a.HandleStreamingCapabilitiesRequest(msg)
	})
	a.MsgHandler.AddHandler(osp.RemotePlaybackAvailabilityRequestKey, func(msg []byte) {
		a.HandleRemotePlaybackAvailabilityRequest(msg)
	})
	a.MsgHandler.AddHandler(osp.PresentationStartRequestKey, func(msg []byte) {
		a.HandlePresentationStartRequest(msg)
	})

	return a
}

func (a *Agent) GetState() osp.RemotePlaybackState {
	a.stateMu.RLock()
	defer a.stateMu.RUnlock()
	return a.state
}

func (a *Agent) SetState(state osp.RemotePlaybackState) {
	a.stateMu.Lock()
	defer a.stateMu.Unlock()
	a.state = state
}

func (a *Agent) GetClientCapabilities() *osp.AuthCapabilities {
	a.capabilitiesMu.RLock()
	defer a.capabilitiesMu.RUnlock()
	return a.clientCapabilities
}

func (a *Agent) SetClientCapabilities(cap *osp.AuthCapabilities) {
	a.capabilitiesMu.Lock()
	defer a.capabilitiesMu.Unlock()
	a.clientCapabilities = cap
}

func (a *Agent) GetClientInfo() ClientInfo {
	a.infoMu.RLock()
	defer a.infoMu.RUnlock()
	return a.clientInfo
}

func (a *Agent) SetClientInfo(info ClientInfo) {
	a.infoMu.Lock()
	defer a.infoMu.Unlock()
	a.clientInfo = info
}

func GetAvailabilities(sources []osp.RemotePlaybackSource, stopAtSuccess bool) []osp.UrlAvailability {
	availabilities := make([]osp.UrlAvailability, 0, len(sources))
	for _, src := range sources {
		if !(src.ExtendedMimeType == `application/vnd.apple.mpegurl` || src.ExtendedMimeType == `audio/mpegurl`) {
			availabilities = append(availabilities, osp.Invalid)
			continue
		}
		rsp, err := http.Head(src.Url)
		if err != nil {
			availabilities = append(availabilities, osp.Unavailable)
			continue
		}
		rsp.Body.Close()
		if rsp.StatusCode != 200 {
			availabilities = append(availabilities, osp.Unavailable)
			continue
		}

		availabilities = append(availabilities, osp.Available)
		if stopAtSuccess {
			return availabilities
		}
	}
	return availabilities
}

func HandleAgent(agent *Agent) {
	defer agent.Conn.CloseWithError(quic.ApplicationErrorCode(0), "agent closed")
	go agent.Listen()

	msg, err := osp.EncodeMessageWithKey(agent.Server.Capabilities, osp.AuthCapabilitiesKey)
	if err != nil {
		agent.Server.Logger.Error(fmt.Sprintf("error encoding capabilities: %s", err.Error()))
		return
	}

	err = osp.SendMessage(agent.Conn, msg)
	if err != nil {
		agent.Server.Logger.Error(fmt.Sprintf("error sending capabilities: %s", err.Error()))
		return
	}

	if agent.GetClientCapabilities() == nil {
		select {
		case <-time.After(defaultTimeout):
			agent.Server.Logger.Error("connection timed out")
			return
		case <-agent.capabilitiesRecv:
			break
		}
	}

	// _, err = agent.Authenticate()
	// if err != nil {
	// 	agent.Server.Logger.Error(fmt.Sprintf("authentication failed: %s", err.Error()))
	// 	return
	// }
	// agent.Server.Logger.Info("authentication success")

	remoteStartRequestChan, err := agent.MsgHandler.ListenForKey(osp.RemotePlaybackStartRequestKey)
	if err != nil {
		panic(err)
	}

	msg = <-remoteStartRequestChan
	req := new(osp.RemotePlaybackStartRequest)
	err = cbor.Unmarshal(msg, req)
	if err != nil {
		agent.Server.Logger.Error(fmt.Sprintf("error unmarshalling remote playback start request: %s", err.Error()))
		return
	}

	agent.Server.Logger.Info("received remote playback start request")

	agent.clientInfo.PlaybackId = req.RemotePlaybackId

	availabilities := GetAvailabilities(pointer.ZeroIfNil(req.Sources), true)
	agent.Server.Logger.Info("got availabilities")
	var source *osp.RemotePlaybackSource = nil
	if availabilities[len(availabilities)-1] != osp.Available {
		agent.Server.Logger.Error("no available source")
		rsp := osp.RemotePlaybackStartResponse{
			Response: osp.Response{ResponseId: osp.ResponseId(req.RequestId)},
		}
		msg, _ := osp.EncodeMessageWithKey(rsp, osp.RemotePlaybackStartResponseKey)
		osp.SendMessage(agent.Conn, msg)
		return
	}

	source = &pointer.ZeroIfNil(req.Sources)[len(availabilities)-1]
	state := osp.RemotePlaybackState{
		Supports: &osp.RemotePlaybackSupports{
			Rate:    false,
			Preload: false,
		},
		Source: source,
	}

	rsp := osp.RemotePlaybackStartResponse{
		Response: osp.Response{ResponseId: osp.ResponseId(req.RequestId)},
		State:    &state,
	}

	msg, _ = osp.EncodeMessageWithKey(rsp, osp.RemotePlaybackStartResponseKey)
	err = osp.SendMessage(agent.Conn, msg)
	if err != nil {
		agent.Server.Logger.Error(fmt.Sprintf("error sending remote playback start response: %s", err.Error()))
		return
	}
	agent.Server.Logger.Info("sent remote playback start response")

	default_controls := osp.RemotePlaybackControls{
		Muted:        pointer.New(false),
		Paused:       pointer.New(false),
		PlaybackRate: pointer.New(1.0),
	}

	var reqControls osp.RemotePlaybackControls
	if req.Controls != nil {
		reqControls = *req.Controls
	} else {
		reqControls = osp.RemotePlaybackControls{}
	}

	reqControls = osp.MergeRemotePlaybackControls(reqControls, default_controls)

	termination := make(chan osp.RemotePlaybackTerminationEventReason)
	go func() {
		termination <- agent.HandleMedia(reqControls, state)
	}()

	reason := <-termination
	term := osp.RemotePlaybackTerminationEvent{
		RemotePlaybackId: agent.clientInfo.PlaybackId,
		Reason:           reason,
	}

	msg, _ = osp.EncodeMessageWithKey(term, osp.RemotePlaybackTerminationEventKey)
	err = osp.SendMessage(agent.Conn, msg)
	if err != nil {
		agent.Server.Logger.Error(fmt.Sprintf("error sending remote playback termination event: %s", err.Error()))
		return
	}
}

func (a *Agent) HandleMedia(initcontrols osp.RemotePlaybackControls, initState osp.RemotePlaybackState) osp.RemotePlaybackTerminationEventReason {
	media, err := a.Server.Player.LoadMediaFromURL(initState.Source.Url)
	fmt.Println(initState.Source.Url)
	if err != nil {
		a.Server.Logger.Error(fmt.Sprintf("error requesting media: %s", err.Error()))
		return osp.UnknownRemotePlaybackTerminationEventReason
	}
	defer media.Release()

	manager, err := a.Server.Player.EventManager()
	if err != nil {
		a.Server.Logger.Error(fmt.Sprintf("error getting event manager: %s", err.Error()))
		return osp.UnknownRemotePlaybackTerminationEventReason
	}

	quit := make(chan struct{})
	pause := make(chan bool)
	position := make(chan osp.MediaTimeline)
	play := make(chan struct{}, 1)
	FreedId, _ := manager.Attach(vlc.MediaFreed, func(e vlc.Event, userData interface{}) {
		close(quit)
	}, nil)

	defer manager.Detach(FreedId)

	EndId, _ := manager.Attach(vlc.MediaPlayerEndReached, func(e vlc.Event, userData interface{}) {
		close(quit)
	}, nil)

	defer manager.Detach(EndId)

	PausedId, _ := manager.Attach(vlc.MediaPlayerPaused, func(e vlc.Event, userData interface{}) {
		pause <- true
	}, nil)

	defer manager.Detach(PausedId)

	PlayingId, _ := manager.Attach(vlc.MediaPlayerPlaying, func(e vlc.Event, userData interface{}) {
		select {
		case play <- struct{}{}:
		case pause <- false:
		}

	}, nil)

	defer manager.Detach(PlayingId)

	PositionId, _ := manager.Attach(vlc.MediaPlayerPositionChanged, func(e vlc.Event, userData interface{}) {
		length, err := a.Server.Player.MediaLength()
		if err != nil {
			return
		}
		p, _ := a.Server.Player.MediaPosition()
		pos := (float64(p) * float64(length)) / float64(time.Second.Milliseconds())
		position <- osp.MediaTimeline(pos)
	}, nil)

	defer manager.Detach(PositionId)

	var success bool = false

	for range pointer.ValIfNil(a.Server.Config.MaxRetries, 1) {
		a.Server.Player.Play()
		select {
		case <-time.After(time.Millisecond * time.Duration(pointer.ValIfNil(a.Server.Config.WaitMs, 500))):
			a.Server.Player.Stop()
			continue
		case <-play:
			fmt.Println("opening")
		}
		success = true
		break
	}

	if !success {
		a.Server.Logger.Error("unable to load media")
		return osp.UnknownRemotePlaybackTerminationEventReason

	}

	a.Server.Logger.Info("here")

	defer a.Server.Player.Stop()

	currentState, _ := HandleControls(initcontrols, a.Server.Player, osp.RemotePlaybackState{}, a.Server.Logger)

	a.SetState(currentState)

	rsp := osp.RemotePlaybackStateEvent{
		RemotePlaybackId: a.clientInfo.PlaybackId,
		State:            currentState,
	}

	msg, _ := osp.EncodeMessageWithKey(rsp, osp.RemotePlaybackStateEventKey)

	err = osp.SendMessage(a.Conn, msg)
	if err != nil {
		a.Server.Logger.Error(fmt.Sprintf("error sending remote playback state event: %s", err.Error()))
		return osp.UnknownRemotePlaybackTerminationEventReason
	}

	remoteModifyRequestChan, err := a.MsgHandler.ListenForKey(osp.RemotePlaybackModifyRequestKey)
	if err != nil {
		panic(err)
	}

	remoteTerminationRequestChan, err := a.MsgHandler.ListenForKey(osp.RemotePlaybackTerminationRequestKey)
	if err != nil {
		panic(err)
	}

	for {
		select {
		case msg := <-remoteModifyRequestChan:
			a.Server.Logger.Info("received remote playback modify request")
			req := new(osp.RemotePlaybackModifyRequest)
			err := cbor.Unmarshal(msg, req)
			if err != nil {
				a.Server.Logger.Error(fmt.Sprintf("error unmarshalling remote playback modify request: %s", err.Error()))
				return osp.UnknownRemotePlaybackTerminationEventReason
			}

			if req.RemotePlaybackId != a.clientInfo.PlaybackId {
				a.Server.Logger.Error("remote playback id mismatch")
				continue
			}

			state, result := HandleControls(req.Controls, a.Server.Player, currentState, a.Server.Logger)

			currentState = state
			a.SetState(currentState)

			rsp := osp.RemotePlaybackModifyResponse{
				Response: osp.Response{ResponseId: osp.ResponseId(req.RequestId)},
				State:    &state,
				Result:   result,
			}

			msg, _ = osp.EncodeMessageWithKey(rsp, osp.RemotePlaybackModifyResponseKey)
			err = osp.SendMessage(a.Conn, msg)
			if err != nil {
				a.Server.Logger.Error(fmt.Sprintf("error sending remote playback modify response: %s", err.Error()))
				return osp.UnknownRemotePlaybackTerminationEventReason
			}

		case <-remoteTerminationRequestChan:
			a.Server.Logger.Info("media terminate")
			return osp.ReceiverCalledTerminate

		case <-quit:
			a.Server.Logger.Info("media quit")
			return osp.ReceiverCalledTerminate
		case b := <-pause:
			var send bool = false
			if currentState.Paused == nil {
				currentState.Paused = pointer.New(b)
				send = true
			} else if *currentState.Paused != b {
				*currentState.Paused = b
				send = true
			}
			if send {
				a.SetState(currentState)
				state := osp.RemotePlaybackStateEvent{
					RemotePlaybackId: a.clientInfo.PlaybackId,
					State: osp.RemotePlaybackState{
						Paused: pointer.New(b),
					},
				}
				msg, _ := osp.EncodeMessageWithKey(state, osp.RemotePlaybackStateEventKey)
				err = osp.SendMessage(a.Conn, msg)
				if err != nil {
					a.Server.Logger.Error(fmt.Sprintf("error sending remote playback state event: %s", err.Error()))
					return osp.UnknownRemotePlaybackTerminationEventReason
				}
			}
		case pos := <-position:
			var send bool = false
			if currentState.Position == nil {
				currentState.Position = pointer.New(pos)
				send = true
			}
			if math.Abs((float64)(pos-*currentState.Position)) > 1 {
				*currentState.Position = pos
				send = true
			}

			if send {
				a.Server.Logger.Info(fmt.Sprintf("media position: %f", pos))
				a.SetState(currentState)
				state := osp.RemotePlaybackStateEvent{
					RemotePlaybackId: a.clientInfo.PlaybackId,
					State: osp.RemotePlaybackState{
						Position: pointer.New(pos),
					},
				}
				msg, _ := osp.EncodeMessageWithKey(state, osp.RemotePlaybackStateEventKey)
				err = osp.SendMessage(a.Conn, msg)
				if err != nil {
					a.Server.Logger.Error(fmt.Sprintf("error sending remote playback state event: %s", err.Error()))
					return osp.UnknownRemotePlaybackTerminationEventReason
				}
			}
		}
	}
}

func HandleControls(controls osp.RemotePlaybackControls, player *vlc.Player, currentState osp.RemotePlaybackState, logger *serverLogger) (state osp.RemotePlaybackState, res osp.Result) {
	state = currentState
	res = osp.Success

	if controls.Paused != nil {
		logger.Info("pausing")
		if player.CanPause() {
			logger.Info(fmt.Sprintf("paused: %t", *controls.Paused))
			err := player.SetPause(*controls.Paused)
			if err != nil {
				logger.Error(fmt.Sprintf("error pausing: %s", err.Error()))
				res = osp.PermanentError
			} else {
				state.Paused = controls.Paused
				logger.Info("pause success")
			}
		} else {
			logger.Info("player can't pause")
			if res == osp.Success {
				res = osp.PermanentError
			}
		}
	}

	if controls.FastSeek != nil {
		if res == osp.Success {
			res = osp.PermanentError
		}
	}

	if controls.Loop != nil {
		if res == osp.Success {
			res = osp.PermanentError
		}
	}

	if controls.Muted != nil {
		player.SetMute(*controls.Muted)
		state.Muted = controls.Muted
	} else {
		logger.Info("controls muted is nil")
	}

	if controls.Volume != nil {
		player.SetVolume(int(*controls.Volume * 100))
		state.Volume = controls.Volume
	}

	if controls.PlaybackRate != nil {
		player.SetPlaybackRate(float32(*controls.PlaybackRate))
		state.PlaybackRate = controls.PlaybackRate
	}

	if controls.Preload != nil {
		if res == osp.Success {
			res = osp.PermanentError
		}
	}

	if controls.Source != nil {
		if res == osp.Success {
			res = osp.PermanentError
		}
	}

	if controls.Poster != nil {
		if res == osp.Success {
			res = osp.PermanentError
		}
	}

	return
}

func Terminate(a *Agent, reason osp.RemotePlaybackTerminationEventReason) {
	term := osp.RemotePlaybackTerminationEvent{
		RemotePlaybackId: a.clientInfo.PlaybackId,
		Reason:           reason,
	}
	msg, _ := osp.EncodeMessageWithKey(term, osp.RemotePlaybackTerminationEventKey)
	osp.SendMessage(a.Conn, msg)
}

func (a *Agent) Listen() {
	for {
		stream, err := a.Conn.AcceptUniStream(context.Background())
		if err != nil {
			a.Server.Logger.Error(fmt.Sprintf("error accepting stream: %s", err.Error()))
			return
		}
		go a.HandleStream(stream)
	}
}

func (a *Agent) HandleStream(stream *quic.ReceiveStream) {
	defer stream.CancelRead(quic.StreamErrorCode(quic.InternalError))
	buff := make([]byte, 9000)
	for {
		n, err := stream.Read(buff)
		a.Server.Logger.Info("stream read")
		if err != nil && !errors.Is(err, io.EOF) {
			val := new(quic.StreamError)
			if errors.As(err, &val) {
				code := val.ErrorCode
				if code == 5139 {
					a.Server.Logger.Error("connection closed")
				}
			}
			return
		}
		if n == 0 {
			return
		}

		handlerr := a.MsgHandler.HandleMessage(buff[:n])
		if handlerr != nil {
			a.Server.Logger.Error(fmt.Sprintf("error handling message: %s", handlerr.Error()))
			return
		}

		if errors.Is(err, io.EOF) {
			return
		}
	}
}

func (a *Agent) HandleRemotePlaybackAvailabilityRequest(msg []byte) {
	req := new(osp.RemotePlaybackAvailabilityRequest)
	err := cbor.Unmarshal(msg, req)
	if err != nil {
		a.Server.Logger.Error(fmt.Sprintf("error unmarshalling availability request: %s", err.Error()))
	}
	availabilities := GetAvailabilities(req.Sources, false)
	rsp := osp.RemotePlaybackAvailabilityResponse{
		Response:          osp.Response{ResponseId: osp.ResponseId(req.RequestId)},
		UrlAvailabilities: availabilities,
	}

	msg, _ = osp.EncodeMessageWithKey(rsp, osp.RemotePlaybackAvailabilityResponseKey)

	err = osp.SendMessage(a.Conn, msg)
	if err != nil {
		a.Server.Logger.Error(fmt.Sprintf("error sending availability response: %s", err.Error()))
		return
	}
}

func (a *Agent) HandleStreamingSessionStartRequest(msg []byte) {
	req := new(osp.StreamingSessionStartRequest)
	err := cbor.Unmarshal(msg, req)
	if err != nil {
		a.Server.Logger.Error(fmt.Sprintf("error unmarshalling start request: %s", err.Error()))
		return
	}

	rsp := osp.StreamingSessionStartResponse{
		Response: osp.Response{ResponseId: osp.ResponseId(req.RequestId)},
		StreamingSessionStartResponseParams: osp.StreamingSessionStartResponseParams{
			Result: osp.Terminating,
		},
	}

	msg, _ = osp.EncodeMessageWithKey(rsp, osp.StreamingSessionStartResponseKey)

	err = osp.SendMessage(a.Conn, msg)
	if err != nil {
		a.Server.Logger.Error(fmt.Sprintf("error sending start response: %s", err.Error()))
		return
	}
}

func (a *Agent) HandleStreamingCapabilitiesRequest(msg []byte) {
	req := new(osp.StreamingCapabilitiesRequest)
	err := cbor.Unmarshal(msg, req)
	if err != nil {
		a.Server.Logger.Error(fmt.Sprintf("error unmarshalling capabilities request: %s", err.Error()))
	}

	rsp := osp.StreamingCapabilities{}

	msg, _ = osp.EncodeMessageWithKey(rsp, osp.StreamingCapabilitiesResponseKey)

	err = osp.SendMessage(a.Conn, msg)
	if err != nil {
		a.Server.Logger.Error(fmt.Sprintf("error sending capabilities response: %s", err.Error()))
		return
	}
}

func (a *Agent) HandlePresentationStartRequest(msg []byte) {
	req := new(osp.PresentationStartRequest)
	err := cbor.Unmarshal(msg, req)
	if err != nil {
		a.Server.Logger.Error(fmt.Sprintf("error unmarshalling start request: %s", err.Error()))
		return
	}

	rsp := osp.PresentationStartResponse{
		Response: osp.Response{ResponseId: osp.ResponseId(req.RequestId)},
		Result:   osp.Terminating,
	}

	msg, _ = osp.EncodeMessageWithKey(rsp, osp.PresentationStartResponseKey)

	err = osp.SendMessage(a.Conn, msg)
	if err != nil {
		a.Server.Logger.Error(fmt.Sprintf("error sending start response: %s", err.Error()))
		return
	}
}

func (a *Agent) HandleAuthCapabilities(msg []byte) {
	capabilities := &osp.AuthCapabilities{}
	err := cbor.Unmarshal(msg, capabilities)
	if err != nil {
		a.Server.Logger.Error(fmt.Sprintf("error unmarshalling capabilities: %s", err.Error()))
		return
	}

	a.SetClientCapabilities(capabilities)
	a.capabilitiesRecv <- true
}

var dictionary = []byte("0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ?!")

func ReadPassword() ([]byte, error) {
	pw := make([]byte, 1000)
	fmt.Print("Input password: ")
	_, err := fmt.Scanln(&pw)
	return pw, err
}

func PrintPassword(pw []byte) {
	fmt.Printf("Password: %s", pw)
}

func (a *Agent) Authenticate() ([]byte, error) {
	var pw []byte
	var status osp.AuthSpake2PskStatus
	cap := a.GetClientCapabilities()
	entropy := max(a.Server.Capabilities.PskMinBitsOfEntropy, cap.PskMinBitsOfEntropy)
	if a.Server.Capabilities.PskEaseOfInput > cap.PskEaseOfInput {
		var err error
		pw, err = ReadPassword()
		if err != nil {
			return pw, fmt.Errorf("failed to read password: %s", err.Error())
		}
		status = osp.PskInput
	} else {
		var err error
		pw, err = randutil.Bytes(rand.Reader, dictionary, int64(math.Ceil(float64(entropy)*(float64(6)/float64(8)))))
		if err != nil {
			panic(err)
		}
		PrintPassword(pw)
		fmt.Print("\n")
		status = osp.PskShown
	}
	B := a.Server.Fingerprint
	connState := a.Conn.ConnectionState()
	A := connState.TLS.PeerCertificates[0].Subject.CommonName[:43]

	w, err := spake2.Generate_w(pw)
	if err != nil {
		a.Server.Logger.Error(fmt.Sprintf("error generating w: %s", err.Error()))
		return nil, errors.Join(err, errors.New("error generating w"))
	}
	y := spake2.RandomScalar()
	pB := spake2.Generate_pB(w, y)

	handshake := osp.AuthSpake2Handshake{
		InitiationToken: osp.AuthInitiationToken{
			Token: &a.Server.AuthToken,
		},
		PskStatus:   status,
		PublicValue: pB.Bytes(),
	}

	msg, _ := osp.EncodeMessageWithKey(handshake, osp.AuthSpake2HandshakeKey)

	err = osp.SendMessage(a.Conn, msg)
	if err != nil {
		a.Server.Logger.Error(fmt.Sprintf("error sending spake handshake: %s", err.Error()))
		return nil, errors.Join(err, errors.New("error sending spake handshake"))
	}
	a.Server.Logger.Info("send spake2 handshake")

	var response osp.AuthSpake2Handshake
	spakeChan, err := a.MsgHandler.ListenForKey(osp.AuthSpake2HandshakeKey)
	if err != nil {
		panic(err)
	}
	rsp := <-spakeChan
	a.Server.Logger.Info("recived spake2 handshake")

	err = cbor.Unmarshal(rsp, &response)
	if err != nil {
		a.Server.Logger.Error(fmt.Sprintf("error unmarshalling spake handshake: %s", err.Error()))
		return nil, errors.Join(err, errors.New("error unmarshalling spake handshake"))
	}

	pA := new(edwards25519.Point)
	pA, err = pA.SetBytes(response.PublicValue)
	if err != nil {
		a.Server.Logger.Error(fmt.Sprintf("error setting pA: %s", err.Error()))
		return nil, errors.Join(err, errors.New("error setting pA"))
	}

	K := spake2.BGenerateK(pA, pB, w, y)

	Ke, cA, cB := spake2.GenerateSecrets(A, B, pA, pB, K, w)

	conf := osp.AuthSpake2Confirmation{
		Bytes: cB,
	}

	msg, err = osp.EncodeMessageWithKey(conf, osp.AuthSpake2ConfirmationKey)
	if err != nil {
		a.Server.Logger.Error(fmt.Sprintf("error encoding spake confirmation: %s", err.Error()))
		return nil, errors.Join(err, errors.New("error encoding spake confirmation"))
	}
	err = osp.SendMessage(a.Conn, msg)
	if err != nil {
		a.Server.Logger.Error(fmt.Sprintf("error sending spake confirmation: %s", err.Error()))
		return nil, errors.Join(err, errors.New("error sending spake confirmation"))
	}
	a.Server.Logger.Info("sent spake2 confirmation")

	spakeConfChan, err := a.MsgHandler.ListenForKey(osp.AuthSpake2ConfirmationKey)
	if err != nil {
		panic(err)
	}
	rsp = <-spakeConfChan
	a.Server.Logger.Info("recived spake2 confirmation")
	confrsp := osp.AuthSpake2Confirmation{
		Bytes: cB,
	}
	err = cbor.Unmarshal(rsp, &confrsp)
	if err != nil {
		a.Server.Logger.Error(fmt.Sprintf("error unmarshalling spake confirmation: %s", err.Error()))
		return nil, errors.Join(err, errors.New("error unmarshalling spake confirmation"))
	}

	if !hmac.Equal(confrsp.Bytes, cA) {
		return nil, errors.New("spake2 confirmation failed")
	}

	return Ke, nil
}

func (s *Server) AcceptConnections() {
	s.Logger.Info("server listening for connections")
	for {
		conn, err := s.Listener.Accept(s.ctx)
		if err != nil {
			s.Logger.Error(fmt.Sprintf("error accepting connection: %s", err.Error()))
			continue
		}

		agent := s.NewAgent(conn)

		go HandleAgent(agent)
	}
}

type serverLogger struct {
	logger *log.Logger
}

func NewServerLogger(logger *log.Logger) *serverLogger {
	return &serverLogger{
		logger: logger,
	}
}

func (s *serverLogger) Info(str string) {
	s.logger.Print(`INFO: ` + str)
}

func (s *serverLogger) Error(str string) {
	s.logger.Print(`ERROR: ` + str)
}

func InstanceName(name []byte) []byte {
	out := make([]byte, 0, 63)
	if len(name) > 63 {
		out = append(out, name[:63]...)
		out = append(out, []byte("\000")...)
	} else {
		out = append(out, name...)
	}

	return out
}

func Addresses(logger *serverLogger) ([]net.IP, error) {
	out := make([]net.IP, 0)
	ifaces, err := net.Interfaces()
	if err != nil {
		return out, errors.Join(err, errors.New("unable to get network interfaces"))
	}
	for _, i := range ifaces {
		addrs, err := i.Addrs()
		if err != nil {
			logger.Error(fmt.Sprintf("error getting addresses for interface %s: %s", i.Name, err.Error()))
			continue
		}

		for _, a := range addrs {
			var ip net.IP
			switch v := a.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}

			if !ip.IsLoopback() && !(ip == nil) {
				out = append(out, ip)
			}
		}
	}

	return out, nil
}

func IsValidRuneEncode(r rune) bool {
	return (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-'
}

func EncodeName(name []rune) []rune {
	out := make([]rune, len(name))
	for i, r := range name {
		if IsValidRuneEncode(r) {
			out[i] = r
		} else {
			out[i] = '-'
		}
	}

	return out
}

func MdnsServer(server *Server, logger *serverLogger) (*mdns.Server, error) {
	IPs, err := Addresses(logger)
	if err != nil {
		logger.Error(fmt.Sprintf("unable to get network interfaces: %s", err.Error()))
		return nil, err
	}

	// mv, _ := vint.EncodeVariableInt30(0)

	instanceName := InstanceName([]byte(*server.Config.DisplayName))

	hexSerialNumber := string(base64.RawStdEncoding.EncodeToString(server.SerialNumber.Bytes()))
	encodedInstanceName := string(EncodeName(bytes.Runes(instanceName)))
	encodedDomain := "local"
	agentHostName := hexSerialNumber + "." + encodedInstanceName + "." + encodedDomain + "."

	service, err := mdns.NewMDNSService(
		string(instanceName),
		server.Config.ServiceName,
		"",
		agentHostName,
		pointer.ValIfNil(server.Config.Port, 7000),
		IPs,
		[]string{"foobar"},
	)
	if err != nil {
		panic(err)
	}

	return mdns.NewServer(&mdns.Config{
		Zone: service,
	})
}
