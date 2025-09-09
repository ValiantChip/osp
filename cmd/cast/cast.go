package cast

import (
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
	"fmt"
	"io"
	"log/slog"
	"math"
	"math/big"
	"net"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"

	"filippo.io/edwards25519"
	osp "github.com/ValiantChip/osp/open_screen"
	"github.com/ValiantChip/osp/spake2"
	"github.com/google/uuid"

	"github.com/fxamacker/cbor/v2"
	"github.com/quic-go/quic-go"

	"github.com/ValiantChip/goutils/pointer"
	randutil "github.com/ValiantChip/goutils/rand"
	cmnd "github.com/ValiantChip/uniCommands"
	"github.com/gabriel-vasile/mimetype"
)

var modelName string = "unset"

var defaultTimeout time.Duration = time.Hour

var terminationTimeout time.Duration = time.Second

type Caster struct {
	client   *Client
	clientMu sync.RWMutex
}

func (c *Caster) GetClient() *Client {
	c.clientMu.RLock()
	defer c.clientMu.RUnlock()
	return c.client
}

func (c *Caster) SetClient(client *Client) {
	c.clientMu.Lock()
	defer c.clientMu.Unlock()
	c.client = client
}

func (c *Caster) Cast(ip net.IP, port int, serverPort int, videoPort int, filename string, at string) error {
	var fl *os.File
	var err error
	if fl, err = os.Open(filename); err != nil {
		slog.Error("failed to open file: %s", "error", err.Error())
		return errors.New("failed to open file")
	}
	defer fl.Close()

	mimeType, err := mimetype.DetectReader(fl)
	if err != nil {
		slog.Error("failed to detect mime type: %s", "error", err.Error())
		return fmt.Errorf("unable to detect mime type")
	}

	addr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(ip.String(), strconv.Itoa(port)))
	if err != nil {
		panic(err)
	}
	udp, err := net.ListenUDP("udp", &net.UDPAddr{Port: serverPort})
	if err != nil {
		panic(err)
	}

	defer udp.Close()

	slog.Info("starting server")

	mux := http.NewServeMux()
	mux.HandleFunc("/video", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, filename)
	})

	svr := &http.Server{Addr: fmt.Sprintf(":%d", videoPort), Handler: mux}

	srverr := make(chan error)
	go func(errchan chan error) {
		errchan <- svr.ListenAndServe()
	}(srverr)

	defer svr.Shutdown(context.Background())

	serialbase, err := rand.Int(rand.Reader, big.NewInt(math.MaxInt32))
	if err != nil {
		panic(err)
	}
	privatekey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}

	spki, err := x509.MarshalPKIXPublicKey(&privatekey.PublicKey)
	if err != nil {
		panic(err)
	}

	s := sha256.Sum256(spki)

	fp := base64.RawStdEncoding.EncodeToString(s[:])
	name := fp + "._openscreen._udp."

	var serialCounter uint32 = 0

	serialNumber := osp.GetSerialNumber(serialbase, serialCounter)

	template := &x509.Certificate{
		Version:            3,
		SerialNumber:       serialNumber,
		Issuer:             pkix.Name{CommonName: modelName},
		Subject:            pkix.Name{CommonName: name},
		SignatureAlgorithm: x509.ECDSAWithSHA256,
		PublicKeyAlgorithm: x509.ECDSA,
		KeyUsage:           x509.KeyUsageDigitalSignature,
	}

	cert, err := x509.CreateCertificate(rand.Reader, template, template, privatekey.Public(), privatekey)
	if err != nil {
		panic(err)
	}
	pair := &tls.Certificate{
		Certificate: [][]byte{cert},
		PrivateKey:  privatekey,
	}

	tlsconfig := &tls.Config{
		Certificates:       []tls.Certificate{*pair},
		NextProtos:         []string{"osp"},
		ServerName:         name,
		InsecureSkipVerify: true,
	}

	quicConfig := &quic.Config{
		MaxIdleTimeout:  2 * time.Minute,
		KeepAlivePeriod: time.Second * 10,
	}

	ctx := context.Background()

	conn, err := quic.Dial(ctx, udp, addr, tlsconfig, quicConfig)
	if err != nil {
		slog.Error("quic dial failed", "error", err.Error())
		return err
	}

	cId := uuid.New()

	client := MakeClient(fp, conn, osp.AuthCapabilities{}, osp.RemotePlaybackId(cId.ID()))

	c.SetClient(client)
	defer c.SetClient(nil)

	errchan := make(chan error)
	go func() { errchan <- client.Listen() }()

	protocolChan := make(chan error)

	go func() {
		protocolChan <- client.HandleProtocol(port, videoPort, mimeType.String())
	}()

	select {
	case <-srverr:
		slog.Info("server shutdown")
		client.Terminate(osp.UnknownTerminationReason)
	case err := <-errchan:
		slog.Error("client listening shutdown", "error", err)
		client.Terminate(osp.UnknownTerminationReason)
	case err := <-protocolChan:
		if err != nil {
			slog.Error("Protocol error", "error", err)
		}
		slog.Info("protocol shutdown")
		client.Terminate(osp.UnknownTerminationReason)
	}
	return nil
}

func (client *Client) HandleProtocol(port int, videoPort int, mimeType string) error {
	// _, err = client.Authenticate()
	// if err != nil {
	// 	client.CloseWithError(errors.New("authentication failed: "+err.Error()), quic.ApplicationErrorCode(quic.ConnectionRefused))
	// }

	// log.Default().Print("Authentication success\n")

	addrs, err := GetAddresses()
	if err != nil {
		slog.Error("error getting outbound address", "error", err.Error())
		return err
	}

	sources := make([]osp.RemotePlaybackSource, len(addrs))
	for i, a := range addrs {
		sources[i] = osp.RemotePlaybackSource{
			Url:              fmt.Sprintf("http://%s:%d/video", a.String(), videoPort),
			ExtendedMimeType: mimeType,
		}
	}

	startRequestHandler := osp.NewRequestHandler()
	client.MsgHandler.AddRequestHandler(osp.RemotePlaybackStartResponseKey, startRequestHandler)

	slog.Debug("sending start request")
	request := osp.RemotePlaybackStartRequest{
		Request: osp.Request{
			RequestId: osp.RequestId(uuid.New().ID()),
		},
		RemotePlaybackId: client.Id,
		Sources:          &sources,
	}

	var response osp.RemotePlaybackStartResponse
	slog.Debug("sent start request")
	err = startRequestHandler.SendRequestWithTimeout(client.Conn, request, &response, osp.RemotePlaybackStartRequestKey, defaultTimeout)
	if err != nil {
		slog.Error("error sending start request")
		return err
	}
	slog.Debug("got start response")

	if response.State == nil {
		slog.Error("request refused")
		return errors.New("request refused")
	}

	client.SetState(*response.State)

	client.SetPlaying(true)
	defer client.SetPlaying(false)

	return client.HandleMedia()
}

func (c *Client) Terminate(reason osp.RemotePlaybackTerminationRequestReason) {
	term := &osp.RemotePlaybackTerminationRequest{
		Request: osp.Request{
			RequestId: osp.RequestId(uuid.New().ID()),
		},
		RemotePlaybackId: c.Id,
		Reason:           reason,
	}
	msg, _ := osp.EncodeMessageWithKey(term, osp.RemotePlaybackTerminationRequestKey)
	osp.SendMessage(c.Conn, msg)
}

type KeyTypeNotRecognizedError struct {
	key uint64
}

func (e KeyTypeNotRecognizedError) Error() string {
	return "key type not recognized: " + strconv.FormatUint(e.key, 10)
}

var errConnectionClosed = errors.New("connection closed")

func GetAddresses() ([]net.IP, error) {
	out := make([]net.IP, 0)
	ifaces, err := net.Interfaces()
	if err != nil {
		return out, errors.Join(err, errors.New("unable to get network interfaces"))
	}
	for _, i := range ifaces {
		addrs, err := i.Addrs()
		if err != nil {
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

type Client struct {
	Id                osp.RemotePlaybackId
	Fingerprint       string
	Conn              *quic.Conn
	Capabilities      osp.AuthCapabilities
	capabilitiesMu    sync.RWMutex
	agentCapabilities *osp.AuthCapabilities
	capabilitiesRecv  chan bool
	infoMu            sync.RWMutex
	agentInfo         osp.AgentInfo
	MsgHandler        *osp.MessageHandler
	ControlsHandler   *cmnd.Handler
	ControlsChan      chan osp.RemotePlaybackControls
	stateMu           sync.RWMutex
	state             osp.RemotePlaybackState
	playing           bool
	playingMu         sync.RWMutex
	// ffmpegCmd         *exec.Cmd
	// ffmpegArgs        []string
}

func MakeClient(fingerprint string, conn *quic.Conn, capabilities osp.AuthCapabilities, id osp.RemotePlaybackId) *Client {
	c := new(Client)
	c.Fingerprint = fingerprint
	c.Conn = conn
	c.Id = id
	c.Capabilities = capabilities
	c.agentCapabilities = nil
	c.capabilitiesRecv = make(chan bool)
	c.ControlsChan = make(chan osp.RemotePlaybackControls, 1)
	c.MsgHandler = osp.NewMessageHandler()
	c.MsgHandler.AddHandler(osp.AuthCapabilitiesKey, func(msg []byte) {
		c.HandleAuthCapabilities(msg)
	})

	c.ControlsHandler = cmnd.NewHandler(cmnd.HandlerArg{
		Name:        "toggle_pause",
		Description: "toggles if the player is paused",
		Runner: func(args []string) error {
			state := c.GetState()
			c.ControlsChan <- osp.RemotePlaybackControls{Paused: pointer.New(!pointer.ValIfNil(state.Paused, false))}
			return nil
		},
	},

		cmnd.HandlerArg{
			Name:        "toggle_mute",
			Description: "toggles if the player is muted",
			Runner: func(args []string) error {
				state := c.GetState()
				c.ControlsChan <- osp.RemotePlaybackControls{Muted: pointer.New(!pointer.ValIfNil(state.Muted, false))}
				return nil
			},
		},
		cmnd.HandlerArg{
			Name:        "seek",
			Description: "Usage: seek <time>\nseek to a specific time in the media: Use HH:MM:SS",
			Runner: func(args []string) error {
				t := args[1]
				//TODO: change time parsing to allow for hours > 24
				tm, err := time.Parse("15:04:05", t)
				if err != nil {
					return errors.New("invalid time format: Use HH:MM:SS")
				}
				timeline := osp.MediaTimeline(tm.Second() + tm.Minute()*60 + tm.Hour()*60*60)
				duration := c.GetState().Duration
				if duration != nil && timeline > *duration {
					return errors.New("cannot seek to a time after the end of the media")
				}
				c.ControlsChan <- osp.RemotePlaybackControls{FastSeek: pointer.New(timeline)}
				return nil
			},
		},
		cmnd.HandlerArg{
			Name:        "current_position",
			Description: "print the current position of the player that is playing the cast media",
			Runner: func(args []string) error {
				position := c.GetState().Position
				if position == nil {
					slog.Error("position is nil")
					fmt.Println("no position has been set")
					return nil
				}

				t := time.Second * time.Duration(*position)

				fmt.Println(ParseDuration(t))

				return nil
			},
		},
		cmnd.HandlerArg{
			Name:        "media_duration",
			Description: "print the duration of the media that is casting",
			Runner: func(args []string) error {
				duration := c.GetState().Duration
				if duration == nil {
					slog.Error("duration is nil")
					fmt.Println("no duration has been set")
					return nil
				}

				t := time.Second * time.Duration(*duration)

				fmt.Println(ParseDuration(t))

				return nil
			},
		},
		cmnd.HandlerArg{
			Name:        "set_volume",
			Description: "Usage: set_volume <0-100>\nsets the volume of the media player",
			Runner: func(args []string) error {
				vol, err := strconv.Atoi(args[1])
				if err != nil {
					return errors.New("invalid volume")
				}
				if vol < 0 || vol > 100 {
					return errors.New("volume must be between 0 and 100")
				}
				c.ControlsChan <- osp.RemotePlaybackControls{Volume: pointer.New(float64(vol) / 100.0)}
				return nil
			},
		},
		cmnd.HandlerArg{
			Name:        "quit",
			Description: "terminate the player and stop casting",
			Runner: func(args []string) error {
				c.Terminate(osp.UserTerminatedViaController)
				return nil
			},
		},

		cmnd.HandlerArg{
			Name:        "help",
			Description: "print this message",
			Runner: func(args []string) error {
				fmt.Println("Available commands:")
				fmt.Print(c.ControlsHandler.GetDescription())
				return nil
			},
		},
	)
	return c
}

func (c *Client) IsPlaying() bool {
	c.playingMu.RLock()
	defer c.playingMu.RUnlock()
	return c.playing
}

func (c *Client) SetPlaying(playing bool) {
	c.playingMu.Lock()
	defer c.playingMu.Unlock()
	c.playing = playing
}

func (c *Client) GetState() osp.RemotePlaybackState {
	c.stateMu.RLock()
	defer c.stateMu.RUnlock()

	return c.state
}

func (c *Client) SetState(state osp.RemotePlaybackState) {
	c.stateMu.Lock()
	defer c.stateMu.Unlock()

	c.state = state
}

func (c *Client) MergeState(state osp.RemotePlaybackState) {
	c.stateMu.Lock()
	defer c.stateMu.Unlock()

	c.state = osp.MergeStates(c.state, state)
}

func (c *Client) GetAgentCapabilities() *osp.AuthCapabilities {
	c.capabilitiesMu.RLock()
	defer c.capabilitiesMu.RUnlock()
	return c.agentCapabilities
}

func (c *Client) SetAgentCapabilities(cap *osp.AuthCapabilities) {
	c.capabilitiesMu.Lock()
	defer c.capabilitiesMu.Unlock()
	c.agentCapabilities = cap
}

func (c *Client) GetAgentInfo() osp.AgentInfo {
	c.infoMu.RLock()
	defer c.infoMu.RUnlock()
	return c.agentInfo
}

func (c *Client) SetAgentInfo(info osp.AgentInfo) {
	c.infoMu.Lock()
	defer c.infoMu.Unlock()
	c.agentInfo = info
}

func (c *Client) CloseWithError(err error, code quic.ApplicationErrorCode) {
	c.Conn.CloseWithError(quic.ApplicationErrorCode(code), err.Error())
	slog.Error(fmt.Sprintf("%s\n", err.Error()))
}

func (c *Client) HandleAuthCapabilities(buff []byte) {
	capabilities := &osp.AuthCapabilities{}
	err := cbor.Unmarshal(buff, capabilities)
	if err != nil {
		return
	}

	c.SetAgentCapabilities(capabilities)
	c.capabilitiesRecv <- true
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

func (c *Client) Authenticate() ([]byte, error) {
	msg, err := osp.EncodeMessageWithKey(c.Capabilities, osp.AuthCapabilitiesKey)
	if err != nil {
		c.CloseWithError(errors.New("failed to get auth capabilities"), quic.ApplicationErrorCode(quic.ConnectionRefused))
		return nil, err
	}

	err = osp.SendMessage(c.Conn, msg)
	if err != nil {
		c.CloseWithError(errors.New("failed to send auth capabilities"), quic.ApplicationErrorCode(quic.ConnectionRefused))
		return nil, err
	}

	if c.GetAgentCapabilities() == nil {
		select {
		case <-time.After(defaultTimeout):
			c.CloseWithError(errors.New("connection timed out"), quic.ApplicationErrorCode(quic.ConnectionRefused))
			return nil, errors.New("connection timed out")
		case <-c.capabilitiesRecv:
			break
		}
	}
	var pw []byte
	var status osp.AuthSpake2PskStatus
	cap := c.GetAgentCapabilities()
	entropy := max(c.Capabilities.PskMinBitsOfEntropy, cap.PskMinBitsOfEntropy)
	if c.Capabilities.PskEaseOfInput >= cap.PskEaseOfInput {
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
		status = osp.PskShown
	}
	A := c.Fingerprint
	B := c.Conn.ConnectionState().TLS.PeerCertificates[0].Subject.CommonName[:43]

	w, err := spake2.Generate_w(pw)
	if err != nil {
		panic(err)
	}

	x := spake2.RandomScalar()

	pA := spake2.Generate_pA(w, x)

	handshake := osp.AuthSpake2Handshake{
		PskStatus:   status,
		PublicValue: pA.Bytes(),
	}
	msg, err = osp.EncodeMessageWithKey(handshake, osp.AuthSpake2HandshakeKey)
	if err != nil {
		return []byte{}, err
	}

	err = osp.SendMessage(c.Conn, msg)
	if err != nil {
		return []byte{}, err
	}

	rspchan, err := c.MsgHandler.ListenForKey(osp.AuthSpake2HandshakeKey)
	if err != nil {
		return []byte{}, err
	}
	rsp := <-rspchan
	response := osp.AuthSpake2Handshake{}
	err = cbor.Unmarshal(rsp, &response)
	if err != nil {
		return []byte{}, err
	}
	if response.PskStatus != osp.PskShown {
		return []byte{}, errors.New("wrong psk status")
	}

	pB := &edwards25519.Point{}
	pB, err = pB.SetBytes(response.PublicValue)
	if err != nil {
		return []byte{}, err
	}

	K := spake2.AGenerateK(pA, pB, w, x)

	Ke, cA, cB := spake2.GenerateSecrets(A, B, pA, pB, K, w)

	conf := osp.AuthSpake2Confirmation{
		Bytes: cA,
	}

	msg, err = osp.EncodeMessageWithKey(conf, osp.AuthSpake2ConfirmationKey)
	if err != nil {
		return []byte{}, err
	}
	err = osp.SendMessage(c.Conn, msg)
	if err != nil {
		return []byte{}, err
	}

	rspchan, err = c.MsgHandler.ListenForKey(osp.AuthSpake2ConfirmationKey)
	if err != nil {
		return []byte{}, err
	}
	rsp = <-rspchan
	var confrsp osp.AuthSpake2Confirmation
	err = cbor.Unmarshal(rsp, &confrsp)
	if err != nil {
		return []byte{}, err
	}

	if !hmac.Equal(confrsp.Bytes, cB) {
		return []byte{}, errors.New("spake2 confirmation failed")
	}

	return Ke, nil
}

func (c *Client) HandleControl(cmd []string) error {
	if !c.IsPlaying() {
		return errors.New("nothing is playing right now")
	}
	err, ok := c.ControlsHandler.HandleArgs(cmd)
	if !ok {
		fmt.Println("Command not recognized: available commands:")
		fmt.Print(c.ControlsHandler.GetDescription())
		return nil
	}

	if err != nil {
		return err
	}

	slog.Debug("sending controls")

	return nil
}

func (c *Client) HandleMedia() error {
	retchan := make(chan error)
	statechan := make(chan osp.RemotePlaybackState)
	updatechan := make(chan osp.RemotePlaybackState)
	rchan := make(chan osp.RemotePlaybackTerminationRequestReason)
	terminationChan := make(chan struct{})
	go func() { retchan <- PlayMedia(c, *time.NewTicker(time.Second), statechan, terminationChan, updatechan) }()

	defer close(terminationChan)

	modifyRequestHandler := osp.NewRequestHandler()
	err := c.MsgHandler.AddRequestHandler(osp.RemotePlaybackModifyResponseKey, modifyRequestHandler)
	if err != nil {
		panic(err)
	}

	stateEventChan, err := c.MsgHandler.ListenForKey(osp.RemotePlaybackStateEventKey)
	if err != nil {
		panic(err)
	}

	terminationEventChan, err := c.MsgHandler.ListenForKey(osp.RemotePlaybackTerminationEventKey)
	if err != nil {
		panic(err)
	}

	terminationResponseChan, err := c.MsgHandler.ListenForKey(osp.RemotePlaybackTerminationResponseKey)
	if err != nil {
		panic(err)
	}

	for {
		select {
		case err := <-retchan:
			slog.Debug("got return")
			return err
		case cont := <-c.ControlsChan:
			slog.Debug("got controls")
			req := osp.RemotePlaybackModifyRequest{
				Request: osp.Request{
					RequestId: osp.RequestId(uuid.New().ID()),
				},
				RemotePlaybackId: c.Id,
				Controls:         cont,
			}

			if cont.Paused != nil {
				slog.Info(fmt.Sprintf("paused: %v", *cont.Paused))
			}

			if cont.Muted != nil {
				slog.Info(fmt.Sprintf("muted: %v", *cont.Muted))
			}

			var modr osp.RemotePlaybackModifyResponse
			slog.Debug("sent modify request")
			err := modifyRequestHandler.SendRequestWithTimeout(c.Conn, req, &modr, osp.RemotePlaybackModifyRequestKey, defaultTimeout)
			if err != nil {
				return errors.Join(errors.New("error sending modify request"), err)
			}

			if modr.Result != osp.Success {
				slog.Error("modify request failed")
				break
			}

			c.MergeState(pointer.ZeroIfNil(modr.State))

			slog.Debug("sent state")
			statechan <- c.GetState()
		case s := <-stateEventChan:
			event := new(osp.RemotePlaybackStateEvent)
			err := cbor.Unmarshal(s, event)
			if err != nil {
				return errors.Join(errors.New("error unmarshalling state event"), err)
			}

			statechan <- event.State
			c.MergeState(event.State)
		case u := <-updatechan:
			c.MergeState(u)
		case term := <-terminationEventChan:
			slog.Debug("got termination event")
			t := osp.RemotePlaybackTerminationEvent{}
			err := cbor.Unmarshal(term, &t)
			if err != nil {
				return errors.Join(errors.New("error unmarshalling termination event"), err)
			}

			slog.Info("Terminated: Reason: %d", "reason", t.Reason)
			return nil
		case reason := <-rchan:
			slog.Debug("got termination reason\n")
			request := osp.RemotePlaybackTerminationRequest{
				Request: osp.Request{
					RequestId: osp.RequestId(uuid.New().ID()),
				},
				RemotePlaybackId: c.Id,
				Reason:           reason,
			}

			msg, _ := osp.EncodeMessageWithKey(request, osp.RemotePlaybackTerminationRequestKey)

			osp.SendMessage(c.Conn, msg)
			slog.Debug("sent termination request\n")

			select {
			case <-terminationResponseChan:
			case <-time.After(terminationTimeout):
			}
			return nil
		}

	}
}

func PlayMedia(c *Client, t time.Ticker, statechan chan osp.RemotePlaybackState, terminationChan chan struct{}, updatechan chan osp.RemotePlaybackState) error {
	state := c.GetState()
	pos := pointer.ZeroIfNil(state.Position)
	var dur osp.MediaTimeline
	dur = pointer.ValIfNil(state.Duration, osp.MediaTimeline(math.MaxFloat64))
	for {
		select {
		case <-t.C:
			if !(pos >= dur) {
				pos += osp.MediaTimeline(pointer.ValIfNil(state.PlaybackRate, 1))
				updatechan <- osp.RemotePlaybackState{
					Position: &pos,
				}
			} else if pos > dur {
				pos = dur
			}
		case s := <-statechan:
			state = s
			cstate := c.GetState()
			pos = pointer.ValIfNil(state.Position, pos)
			dur = pointer.ValIfNil(state.Duration, pointer.ValIfNil(cstate.Duration, dur))
		case <-terminationChan:
			return nil
		}

	}
}

func (c *Client) HandleStream(stream *quic.ReceiveStream) error {
	if stream == nil {
		return errors.New("stream is nil")
	}
	buff := make([]byte, 9000)
	for {
		n, err := stream.Read(buff)
		if err != nil && !errors.Is(err, io.EOF) {
			return err
		}
		if n == 0 {
			continue
		}

		c.MsgHandler.HandleMessage(buff[:n])

		if errors.Is(err, io.EOF) {
			return nil
		}
	}
}

func (c *Client) Listen() error {
	streamerr := make(chan error)
	go func() {
		for {
			stream, err := c.Conn.AcceptUniStream(context.Background())
			if err != nil {
				streamerr <- err
			}
			go func() { streamerr <- c.HandleStream(stream) }()
		}
	}()

	for {
		quicErr := &quic.StreamError{}
		select {
		case err := <-streamerr:
			if err == nil {
				continue
			}
			if errors.As(err, &quicErr) {
				if quicErr.ErrorCode == 5139 {
					return errConnectionClosed
				}
			} else {
				slog.Error("error accepting stream: %s", "error", err.Error())
				return err
			}
		}
	}
}

func ParseDuration(duration time.Duration) string {
	seconds := int(duration.Seconds()) % 60
	minutes := int(duration.Minutes()) % 60
	hours := int(duration.Hours()) % 60
	if hours > 0 {
		return fmt.Sprintf("%02d:%02d:%02d", hours, minutes, seconds)
	} else {
		if minutes > 0 {
			return fmt.Sprintf("%02d:%02d", minutes, seconds)
		} else {
			return fmt.Sprintf("%02d", seconds)
		}
	}
}
