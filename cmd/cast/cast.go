package cast

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"math/big"
	"net"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"

	osp "github.com/CzarJoti/osp/open_screen"
	"github.com/google/uuid"

	"github.com/quic-go/quic-go"

	spake2 "github.com/CzarJoti/gospake2"
	"github.com/CzarJoti/goutils/pointer"
	randutil "github.com/CzarJoti/goutils/rand"
	sliceutil "github.com/CzarJoti/goutils/slices"
	cmnd "github.com/CzarJoti/uniCommands"
	"github.com/gabriel-vasile/mimetype"
)

var modelName string = "unset"

var defaultTimeout time.Duration = time.Hour

var terminationTimeout time.Duration = time.Second

var capabilites = []osp.AgentCapability{
	osp.ControlRemotePlayback,
}

var requiredCapabilities = []osp.AgentCapability{
	osp.RecieveRemotePlayback,
}

var AUTH_CAPABILITIES = osp.AuthCapabilities{
	PskEaseOfInput:      100,
	PskInputMethods:     []osp.PskInputMethod{osp.Numeric},
	PskMinBitsOfEntropy: 32,
}

type Caster struct {
	runningClient         *Client
	logger                *slog.Logger
	Transport             *quic.Transport
	DisplayName           string
	clientMu              sync.RWMutex
	AuthenticationChan    chan []byte
	AuthenticationRequest chan any
	Locale                string
}

func NewCaster(clientPort int, logger *slog.Logger) *Caster {
	slog.SetDefault(logger)
	udp, err := net.ListenUDP("udp", &net.UDPAddr{Port: clientPort})
	if err != nil {
		panic(err)
	}

	transport := &quic.Transport{
		Conn: udp,
	}

	return &Caster{
		AuthenticationChan:    make(chan []byte),
		AuthenticationRequest: make(chan any),
		Transport:             transport,
	}
}

func (c *Caster) GetClient() *Client {
	c.clientMu.RLock()
	defer c.clientMu.RUnlock()
	return c.runningClient
}

func (c *Caster) SetClient(client *Client) {
	c.clientMu.Lock()
	defer c.clientMu.Unlock()
	c.runningClient = client
}

func (c *Caster) EstablishConnection(ip net.IP, serverPort int, handleAuthentication bool) (*Client, error) {
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

	tlsconfig := tls.Config{
		Certificates:       []tls.Certificate{*pair},
		NextProtos:         []string{"osp"},
		ServerName:         name,
		InsecureSkipVerify: true,
	}

	quicConfig := quic.Config{
		MaxIdleTimeout:  2 * time.Minute,
		KeepAlivePeriod: time.Second * 10,
	}

	ctx := context.Background()

	addr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(ip.String(), strconv.Itoa(serverPort)))
	if err != nil {
		panic(err)
	}

	conn, err := c.Transport.Dial(ctx, addr, &tlsconfig, &quicConfig)
	if err != nil {
		return nil, err
	}

	cId := uuid.New()

	client := c.MakeClient(fp, conn, AUTH_CAPABILITIES, osp.RemotePlaybackId(cId.ID()), c.AuthenticationChan, handleAuthentication)

	return client, nil
}

func (c *Caster) VerifyDevice(ip net.IP, port int, timeout time.Duration) error {
	client, err := c.EstablishConnection(ip, port, false)
	if err != nil {
		slog.Info("unable to establish connection to device", "ip", ip.String())
		return err
	}

	errchan := make(chan error, 1)
	donechan := make(chan error, 1)
	go func() {
		errchan <- client.Listen()
	}()

	go func() {
		var err error
		defer func() {
			select {
			case donechan <- err:
			default:
			}
		}()
		requestHandler := osp.NewRequestHandler()
		er := client.MsgHandler.AddRequestHandler(osp.AgentInfoResponseKey, requestHandler)
		if er != nil {
			panic(er)
		}

		request := osp.AgentInfoRequest{
			Request: osp.Request{
				RequestId: osp.RequestId(uuid.New().ID()),
			},
		}

		slog.Debug("sending agent info request")
		data, err := requestHandler.SendRequestWithTimeout(client.Conn, request, osp.AgentInfoRequestKey, timeout)
		if err != nil {
			if errors.Is(err, osp.ErrRequestTimeout) {
				slog.Debug("request timed out")
			} else {
				slog.Debug("error sending agent info request", "error", err.Error())
			}
			return
		} else {
			slog.Debug("received agent info response")
		}

		rsp := data.(osp.AgentInfoResponse)

		if !sliceutil.ContainsAll(rsp.AgentInfo.Capabilities, requiredCapabilities) {
			slog.Debug("missing required capabilities")
			err = errors.New("missing required capabilities")
			return
		}
	}()

	for {
		select {
		case err := <-errchan:
			slog.Debug("connection closed", "error", err)
			if err == errConnectionClosed {
				return nil
			}
			return err
		case err := <-donechan:
			if err != nil {
				return err
			}
			return nil
		}
	}
}

func (c *Caster) Stream(ip net.IP, serverPort int, filename string) error {
	var fl *os.File
	var err error
	if fl, err = os.Open(filename); err != nil {
		slog.Error("failed to open file: %s", "error", err.Error())
		return errors.New("failed to open file")
	}
	defer fl.Close()

	return nil
}

func (c *Caster) Cast(ip net.IP, serverPort int, videoPort int, filename string, at string) error {
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

	client, err := c.EstablishConnection(ip, serverPort, true)
	if err != nil {
		slog.Error("failed to establish connection", "error", err.Error())
		return err
	}

	c.SetClient(client)
	defer c.SetClient(nil)

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

	errchan := make(chan error)
	go func() { errchan <- client.Listen() }()

	protocolChan := make(chan error)

	go func() {
		protocolChan <- client.HandleProtocol(serverPort, videoPort, mimeType.String())
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
	_, err := client.Authenticate()
	if err != nil {
		fmt.Println("Authentication failed")
		slog.Error(err.Error())
		client.CloseWithError(errors.New("authentication failed: "+err.Error()), quic.ApplicationErrorCode(quic.ConnectionRefused))
	}

	fmt.Println("Authentication success")

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

	slog.Debug("sent start request")
	data, err := startRequestHandler.SendRequestWithTimeout(client.Conn, request, osp.RemotePlaybackStartRequestKey, defaultTimeout)
	if err != nil {
		slog.Error("error sending start request")
		return err
	}
	slog.Debug("got start response")

	response := data.(*osp.RemotePlaybackStartResponse)

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
	Id                    osp.RemotePlaybackId
	Fingerprint           string
	Conn                  *quic.Conn
	packetConn            net.PacketConn
	Capabilities          osp.AuthCapabilities
	capabilitiesMu        sync.RWMutex
	agentCapabilities     *osp.AuthCapabilities
	capabilitiesRecv      chan bool
	infoMu                sync.RWMutex
	agentInfo             osp.AgentInfo
	ClientInfo            osp.AgentInfo
	MsgHandler            *osp.MessageHandler
	ControlsHandler       *cmnd.Handler
	ControlsChan          chan osp.RemotePlaybackControls
	authenticationChan    chan []byte
	authenticationRequest chan any
	stateMu               sync.RWMutex
	state                 osp.RemotePlaybackState
	playing               bool
	playingMu             sync.RWMutex
	// ffmpegCmd         *exec.Cmd
	// ffmpegArgs        []string
}

func (caster *Caster) MakeClient(fingerprint string, conn *quic.Conn, capabilities osp.AuthCapabilities, id osp.RemotePlaybackId, authChan chan []byte, handleAuthentication bool) *Client {
	c := new(Client)
	c.Fingerprint = fingerprint
	c.Conn = conn
	c.Id = id
	token := osp.NewStateToken(osp.STATE_TOKEN_LENGTH)
	c.ClientInfo = osp.AgentInfo{
		DisplayName:  caster.DisplayName,
		Capabilities: capabilites,
		Locales:      []string{caster.Locale},
		StateToken:   token,
	}
	c.Capabilities = capabilities
	c.authenticationChan = authChan
	c.authenticationRequest = caster.AuthenticationRequest
	c.agentCapabilities = nil
	c.capabilitiesRecv = make(chan bool)
	c.ControlsChan = make(chan osp.RemotePlaybackControls, 1)
	c.MsgHandler = osp.NewMessageHandler()
	if handleAuthentication {
		c.MsgHandler.AddHandler(osp.AuthCapabilitiesKey, func(data any) {
			cap := data.(*osp.AuthCapabilities)
			c.HandleAuthCapabilities(cap)
		})
	}

	c.MsgHandler.AddHandler(osp.AgentInfoRequestKey, func(data any) {
		req := data.(*osp.AgentInfoRequest)
		c.HandleInfoRequest(req)
	})

	c.ControlsHandler = cmnd.NewHandler(
		cmnd.HandlerArg{
			Name: "toggle_pause",
			Runner: func(args []string) error {
				state := c.GetState()
				c.ControlsChan <- osp.RemotePlaybackControls{Paused: pointer.New(!pointer.ValIfNil(state.Paused, false))}
				return nil
			},
		},
		cmnd.HandlerArg{
			Name: "toggle_mute",
			Runner: func(args []string) error {
				state := c.GetState()
				c.ControlsChan <- osp.RemotePlaybackControls{Muted: pointer.New(!pointer.ValIfNil(state.Muted, false))}
				return nil
			},
		},
		cmnd.HandlerArg{
			Name: "seek",
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
			Name: "current_position",
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
			Name: "media_duration",
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
			Name: "set_volume",
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
			Name: "quit",
			Runner: func(args []string) error {
				c.Terminate(osp.UserTerminatedViaController)
				return nil
			},
		},
	)
	return c
}

func (c *Client) HandleInfoRequest(req *osp.AgentInfoRequest) {

	rsp := osp.AgentInfoResponse{
		Response:  osp.Response{ResponseId: osp.ResponseId(req.RequestId)},
		AgentInfo: c.ClientInfo,
	}

	msg, _ := osp.EncodeMessageWithKey(rsp, osp.AgentInfoResponseKey)
	osp.SendMessage(c.Conn, msg)
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

func (c *Client) HandleAuthCapabilities(cap *osp.AuthCapabilities) {
	c.SetAgentCapabilities(cap)
	c.capabilitiesRecv <- true
}

var dictionary = []byte(randutil.ALPHA_NUMERIC + "?!")

func ReadPassword(authChan chan []byte, authRequest chan any) ([]byte, error) {
	slog.Info("requesting password")
	authRequest <- struct{}{}
	pw := <-authChan
	return pw, nil
}

func PrintPassword(pw []byte) {
	fmt.Printf("Password: %s", pw)
}

func (c *Client) Authenticate() ([]byte, error) {
	handshakechan, _ := c.MsgHandler.ListenForKey(osp.AuthSpake2HandshakeKey)
	confChan, _ := c.MsgHandler.ListenForKey(osp.AuthSpake2ConfirmationKey)
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

	A := c.Fingerprint
	B := c.Conn.ConnectionState().TLS.PeerCertificates[0].Subject.CommonName[:43]
	var s spake2.Spake2Handler
	if c.Capabilities.PskEaseOfInput >= cap.PskEaseOfInput {
		var err error
		pw, err = ReadPassword(c.authenticationChan, c.authenticationRequest)
		if err != nil {
			return pw, fmt.Errorf("failed to read password: %s", err.Error())
		}
		status = osp.PskInput

		s, err = spake2.NewA(pw, A, B, rand.Reader, spake2.DEFAULT_SUITE)
		if err != nil {
			return nil, fmt.Errorf("failed to init spake2: %s", err.Error())
		}
	} else {
		var err error
		pw, err = randutil.Bytes(rand.Reader, dictionary, int64(math.Ceil(float64(entropy)/(osp.CalculateBitsOfEntropy(dictionary)))))
		if err != nil {
			panic(err)
		}
		PrintPassword(pw)
		status = osp.PskShown

		s, err = spake2.NewB(pw, A, B, rand.Reader, spake2.DEFAULT_SUITE)
		if err != nil {
			return nil, fmt.Errorf("failed to init spake2: %s", err.Error())
		}
	}

	msg, err = s.Start()
	if err != nil {
		return nil, fmt.Errorf("failed to start spake2: %s", err.Error())
	}

	handshake := osp.AuthSpake2Handshake{
		PskStatus:   status,
		PublicValue: msg,
	}
	msg, err = osp.EncodeMessageWithKey(handshake, osp.AuthSpake2HandshakeKey)
	if err != nil {
		return []byte{}, err
	}

	err = osp.SendMessage(c.Conn, msg)
	if err != nil {
		return []byte{}, err
	}

	slog.Info("sent spake2 handshake")

	rsp := <-handshakechan

	slog.Info("received spake2 handshake")

	response := rsp.(*osp.AuthSpake2Handshake)
	if response.PskStatus == status {
		return []byte{}, errors.New("wrong psk status")
	}

	key, confm, err := s.Finish(response.PublicValue)

	conf := osp.AuthSpake2Confirmation{
		Bytes: confm,
	}

	msg, err = osp.EncodeMessageWithKey(conf, osp.AuthSpake2ConfirmationKey)
	if err != nil {
		return []byte{}, err
	}
	err = osp.SendMessage(c.Conn, msg)
	slog.Info("sent spake2 confirmation")
	if err != nil {
		return []byte{}, err
	}
	rsp = <-confChan

	slog.Info("received spake2 confirmation")
	confrsp := rsp.(*osp.AuthSpake2Confirmation)

	err = s.Verify(confrsp.Bytes)
	if err != nil {
		return []byte{}, fmt.Errorf("verification failed")
	}

	return key, nil
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

			slog.Debug("sent modify request")
			data, err := modifyRequestHandler.SendRequestWithTimeout(c.Conn, req, osp.RemotePlaybackModifyRequestKey, defaultTimeout)
			if err != nil {
				return errors.Join(errors.New("error sending modify request"), err)
			}

			modr := data.(*osp.RemotePlaybackModifyResponse)

			if modr.Result != osp.Success {
				slog.Error("modify request failed")
				break
			}

			c.MergeState(pointer.ZeroIfNil(modr.State))

			slog.Debug("sent state")
			statechan <- c.GetState()
		case s := <-stateEventChan:
			event := s.(*osp.RemotePlaybackStateEvent)

			statechan <- event.State
			c.MergeState(event.State)
		case u := <-updatechan:
			c.MergeState(u)
		case term := <-terminationEventChan:
			slog.Debug("got termination event")
			t := term.(*osp.RemotePlaybackTerminationEvent)

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
	s := osp.NewScanner(stream)
	for {
		ok := s.Scan()
		if !ok {
			return s.Err()
		}

		key, data := s.GetVal()
		c.MsgHandler.HandleData(key, data)
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
