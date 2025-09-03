package main

import (
	"bufio"
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
	"log"
	"math"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
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
)

var modelName string = "unset"

var folder string = "./chunks"

var defaultTimeout time.Duration = 10 * time.Second

var terminationTimeout time.Duration = time.Second

func main() {

	ip := net.ParseIP(os.Args[1])
	if ip == nil {
		panic("invalid ip")
	}
	port, err := strconv.Atoi(os.Args[2])
	if err != nil {
		panic(err)
	}

	filename := os.Args[3]

	addr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(ip.String(), strconv.Itoa(port)))
	if err != nil {
		panic(err)
	}
	udp, err := net.ListenUDP("udp", &net.UDPAddr{Port: 6121})
	if err != nil {
		panic(err)
	}

	fmt.Println("starting ffmpeg")
	os.RemoveAll(folder)
	os.Mkdir(folder, os.ModePerm)
	fl, _ := os.Create(folder + "/playlist.m3u8")
	fl.Close()
	cmd := exec.CommandContext(context.Background(), "ffmpeg", "-y",
		"-i", filename,
		"-preset", "fast",
		"-threads", "0",
		"-f", "hls",
		"-hls_list_size", "0",
		"-hls_time", "10",
		"-hls_playlist_type", "event",
		"-hls_flags", "independent_segments+append_list",
		"-master_pl_name", "playlist.m3u8",
		"-hls_segment_filename", folder+`/%v_%03d.ts`, folder+`/%v.m3u8`,
	)

	//_, writer := io.Pipe()
	// cmd.Stdout = os.Stdout
	// cmd.Stderr = os.Stderr
	cmderrchan := make(chan error)
	go func() { cmderrchan <- cmd.Run() }()
	defer func() {
		if cmd.Process != nil {
			cmd.Process.Kill()
		}
	}()

	fmt.Println("starting server")

	http.Handle("/files/", http.StripPrefix(`/files/`, http.FileServer(http.Dir(folder))))

	srverr := make(chan error)
	go func(errchan chan error) {
		errchan <- http.ListenAndServe(fmt.Sprintf(":%d", port), nil)
	}(srverr)

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
		panic(err)
	}

	cId := uuid.New()

	client := MakeClient(fp, conn, osp.AuthCapabilities{}, osp.RemotePlaybackId(cId.ID()))
	errchan := make(chan error)
	go func() { errchan <- client.Listen() }()

	protocolChan := make(chan error)

	go func() {
		protocolChan <- client.HandleProtocol(port)
	}()

	select {
	case err := <-srverr:
		fmt.Printf("server shutdown: %v\n", err)
		client.Terminate(osp.UnknownTerminationReason)
	case err := <-errchan:
		fmt.Printf("client listening shutdown: %v\n", err)
		client.Terminate(osp.UnknownTerminationReason)
	case err := <-protocolChan:
		if err != nil {
			fmt.Printf("Protocol error: %v\n", err)
		}
		fmt.Println("protocol shutdown")
		client.Terminate(osp.UnknownTerminationReason)
	}

	fmt.Printf("Done\n")
}

func (client *Client) HandleProtocol(port int) error {
	msg, err := osp.EncodeMessageWithKey(client.Capabilities, osp.AuthCapabilitiesKey)
	if err != nil {
		client.CloseWithError(errors.New("failed to get auth capabilities"), quic.ApplicationErrorCode(quic.ConnectionRefused))
		return err
	}

	err = osp.SendMessage(client.Conn, msg)
	if err != nil {
		client.CloseWithError(errors.New("failed to send auth capabilities"), quic.ApplicationErrorCode(quic.ConnectionRefused))
		return err
	}

	if client.GetAgentCapabilities() == nil {
		select {
		case <-time.After(defaultTimeout):
			client.CloseWithError(errors.New("connection timed out"), quic.ApplicationErrorCode(quic.ConnectionRefused))
			return errors.New("connection timed out")
		case <-client.capabilitiesRecv:
			break
		}
	}
	// _, err = client.Authenticate()
	// if err != nil {
	// 	client.CloseWithError(errors.New("authentication failed: "+err.Error()), quic.ApplicationErrorCode(quic.ConnectionRefused))
	// }

	// log.Default().Print("Authentication success\n")

	addrs, err := GetAddresses()
	if err != nil {
		fmt.Printf("error getting outbound address: %s\n", err.Error())
		return err
	}

	fmt.Println("got outbound address")

	sources := make([]osp.RemotePlaybackSource, len(addrs))
	for i, a := range addrs {
		sources[i] = osp.RemotePlaybackSource{
			Url:              fmt.Sprintf("http://%s:%d/files/playlist.m3u8", a.String(), port),
			ExtendedMimeType: "application/vnd.apple.mpegurl",
		}
	}

	startRequestHandler := osp.NewRequestHandler()
	client.MsgHandler.AddRequestHandler(osp.RemotePlaybackStartResponseKey, startRequestHandler)

	fmt.Println("sending start request")
	request := osp.RemotePlaybackStartRequest{
		Request: osp.Request{
			RequestId: osp.RequestId(uuid.New().ID()),
		},
		RemotePlaybackId: client.Id,
		Sources:          &sources,
	}

	var response osp.RemotePlaybackStartResponse
	fmt.Println("sent start request")
	err = startRequestHandler.SendRequestWithTimeout(client.Conn, request, &response, osp.RemotePlaybackStartRequestKey, defaultTimeout)
	if err != nil {
		fmt.Printf("error sending message\n")
		return err
	}
	fmt.Println("got start response")

	if response.State == nil {
		fmt.Printf("request refused\n")
		return errors.New("request refused")
	}

	client.SetState(*response.State)

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
	ControlsChan      chan osp.RemotePlaybackControls
	stateMu           sync.RWMutex
	state             osp.RemotePlaybackState
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
	return c
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
	log.Fatalf("%s\n", err.Error())
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
	msg, err := osp.EncodeMessageWithKey(handshake, osp.AuthSpake2HandshakeKey)
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

func (c *Client) HandleControls() osp.RemotePlaybackTerminationRequestReason {
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		cmd := strings.Split(scanner.Text(), " ")
		cont := osp.RemotePlaybackControls{}
		switch cmd[0] {
		case "toggle_pause":
			state := c.GetState()
			cont.Paused = pointer.New(!pointer.ValIfNil(state.Paused, false))
		case "toggle_mute":
			state := c.GetState()
			cont.Muted = pointer.New(!pointer.ValIfNil(state.Muted, false))
		case "quit":
			return osp.UserTerminatedViaController
		default:
			log.Println("command not recognized")
			continue
		}

		fmt.Printf("Sending controls\n")
		c.ControlsChan <- cont
	}

	return osp.UnknownTerminationReason
}

func (c *Client) HandleMedia() error {
	retchan := make(chan error)
	statechan := make(chan osp.RemotePlaybackState)
	updatechan := make(chan osp.RemotePlaybackState)
	rchan := make(chan osp.RemotePlaybackTerminationRequestReason)
	terminationChan := make(chan struct{})
	go func() { retchan <- PlayMedia(c, *time.NewTicker(time.Second), statechan, terminationChan, updatechan) }()

	go func() { rchan <- c.HandleControls() }()

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
			fmt.Println("got return")
			return err
		case cont := <-c.ControlsChan:
			fmt.Println("got controls")
			req := osp.RemotePlaybackModifyRequest{
				Request: osp.Request{
					RequestId: osp.RequestId(uuid.New().ID()),
				},
				RemotePlaybackId: c.Id,
				Controls:         cont,
			}

			if cont.Paused != nil {
				log.Printf("paused: %v", *cont.Paused)
			}

			if cont.Muted != nil {
				log.Printf("muted: %v", *cont.Muted)
			}

			var modr osp.RemotePlaybackModifyResponse
			fmt.Println("sent modify request")
			err := modifyRequestHandler.SendRequestWithTimeout(c.Conn, req, &modr, osp.RemotePlaybackModifyRequestKey, defaultTimeout)
			if err != nil {
				return errors.Join(errors.New("error sending modify request"), err)
			}

			if modr.State.Paused != nil {
				log.Printf("modr paused: %v", *modr.State.Paused)
			} else {
				log.Printf("modr paused is nil")
			}

			if modr.Result != osp.Success {
				log.Println("modify request failed")
				break
			}

			c.MergeState(pointer.ZeroIfNil(modr.State))

			fmt.Println("sent state")
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
			fmt.Println("got termination event")
			t := osp.RemotePlaybackTerminationEvent{}
			err := cbor.Unmarshal(term, &t)
			if err != nil {
				return errors.Join(errors.New("error unmarshalling termination event"), err)
			}

			fmt.Printf("Terminated: Reason: %d", t.Reason)
			return nil
		case reason := <-rchan:
			fmt.Printf("got termination reason\n")
			request := osp.RemotePlaybackTerminationRequest{
				Request: osp.Request{
					RequestId: osp.RequestId(uuid.New().ID()),
				},
				RemotePlaybackId: c.Id,
				Reason:           reason,
			}

			msg, _ := osp.EncodeMessageWithKey(request, osp.RemotePlaybackTerminationRequestKey)

			osp.SendMessage(c.Conn, msg)
			fmt.Printf("sent termination request\n")

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
				fmt.Printf("error accepting stream: %s", err.Error())
				return err
			}
		}
	}
}
