package open_screen

import (
	"errors"
	"math"
	"math/big"

	"crypto/rand"

	randutil "github.com/CzarJoti/goutils/rand"
	vint "github.com/CzarJoti/osp/variable_int"
	"github.com/fxamacker/cbor/v2"
	"github.com/quic-go/quic-go"
)

const STATE_TOKEN_LENGTH = 8

const STATE_TOKEN_DICTIONARY = randutil.ALPHA_NUMERIC

func NewStateToken(length int) string {
	token, _ := randutil.Bytes(rand.Reader, []byte(STATE_TOKEN_DICTIONARY), int64(length))
	return string(token)
}

func CalculateBitsOfEntropy(dictionary []byte) float64 {
	return math.Log2(float64(len(dictionary)))
}

func SeperateVint(buff []byte) (uint64, []byte) {
	b := buff[0]
	length := vint.GetLength(b)
	key := vint.GetValue(buff, length)

	return key, buff[length:]
}

func EncodeMessageWithKey(v any, key TypeKey) ([]byte, error) {
	prefix, err := vint.EncodeVariableInt30(uint32(key))
	if err != nil {
		return nil, err
	}

	buff, err := cbor.Marshal(v)
	if err != nil {
		return nil, err
	}

	msg := make([]byte, len(prefix), len(prefix)+len(buff))
	copy(msg, prefix)
	msg = append(msg, buff...)

	return msg, nil
}

var ErrConnectionClosed = errors.New("connection closed")

func SendMessage(conn *quic.Conn, msg []byte) error {
	stream, err := conn.OpenUniStream()
	if err != nil {
		val := new(quic.StreamError)
		if errors.As(err, &val) {
			code := val.ErrorCode
			if code == 5139 {
				return ErrConnectionClosed
			}

		}
		return err
	}

	defer stream.Close()

	_, err = stream.Write(msg)
	if err != nil {
		val := new(quic.StreamError)
		if errors.As(err, &val) {
			code := val.ErrorCode
			if code == 5139 {
				return ErrConnectionClosed
			}
		}
		return err
	}
	return nil
}

func GetSerialNumber(base *big.Int, counter uint32) *big.Int {
	return big.NewInt(base.Int64()<<32 | int64(counter))
}

func MergeStates(a RemotePlaybackState, b RemotePlaybackState) RemotePlaybackState {
	if b.Supports != nil {
		a.Supports = b.Supports
	}
	if b.Source != nil {
		a.Source = b.Source
	}
	if b.Loading != nil {
		a.Loading = b.Loading
	}
	if b.Loaded != nil {
		a.Loaded = b.Loaded
	}
	if b.Error != nil {
		a.Error = b.Error
	}
	if b.Epoch != nil {
		a.Epoch = b.Epoch
	}
	if b.Duration != nil {
		a.Duration = b.Duration
	}
	if b.BufferedTimeRanges != nil {
		a.BufferedTimeRanges = b.BufferedTimeRanges
	}
	if b.SeekableTimeRanges != nil {
		a.SeekableTimeRanges = b.SeekableTimeRanges
	}
	if b.PlayedTimeRanges != nil {
		a.PlayedTimeRanges = b.PlayedTimeRanges
	}
	if b.Position != nil {
		a.Position = b.Position
	}
	if b.PlaybackRate != nil {
		a.PlaybackRate = b.PlaybackRate
	}
	if b.Paused != nil {
		a.Paused = b.Paused
	}
	if b.Seeking != nil {
		a.Seeking = b.Seeking
	}
	if b.Stalled != nil {
		a.Stalled = b.Stalled
	}
	if b.Ended != nil {
		a.Ended = b.Ended
	}
	if b.Volume != nil {
		a.Volume = b.Volume
	}
	if b.Muted != nil {
		a.Muted = b.Muted
	}
	if b.Resolution != nil {
		a.Resolution = b.Resolution
	}
	if b.AudioTracks != nil {
		a.AudioTracks = b.AudioTracks
	}
	if b.VideoTracks != nil {
		a.VideoTracks = b.VideoTracks
	}
	if b.TextTracks != nil {
		a.TextTracks = b.TextTracks
	}
	return a
}

func MergeRemotePlaybackControls(a RemotePlaybackControls, b RemotePlaybackControls) RemotePlaybackControls {
	if b.Source != nil {
		a.Source = b.Source
	}

	if b.Preload != nil {
		a.Preload = b.Preload
	}

	if b.Loop != nil {
		a.Loop = b.Loop
	}

	if b.Paused != nil {
		a.Paused = b.Paused
	}

	if b.Muted != nil {
		a.Muted = b.Muted
	}

	if b.Volume != nil {
		a.Volume = b.Volume
	}

	if b.Seek != nil {
		a.Seek = b.Seek
	}

	if b.FastSeek != nil {
		a.FastSeek = b.FastSeek
	}

	if b.PlaybackRate != nil {
		a.PlaybackRate = b.PlaybackRate
	}

	if b.Poster != nil {
		a.Poster = b.Poster
	}

	if b.EnabledAudioTrackIds != nil {
		a.EnabledAudioTrackIds = b.EnabledAudioTrackIds
	}

	if b.SelectedVideoTrackId != nil {
		a.SelectedVideoTrackId = b.SelectedVideoTrackId
	}

	if b.AddedTextTracks != nil {
		a.AddedTextTracks = b.AddedTextTracks
	}

	if b.ChangedTextTracks != nil {
		a.ChangedTextTracks = b.ChangedTextTracks
	}

	return a
}

type TypeKey = uint64

const NUM_MESSAGES = 46

type GetZeroVal func() any

var typeMap = map[TypeKey]GetZeroVal{
	AuthCapabilitiesKey:                    func() any { return new(AuthCapabilities) },
	AuthSpake2HandshakeKey:                 func() any { return new(AuthSpake2Handshake) },
	AuthSpake2ConfirmationKey:              func() any { return new(AuthSpake2Confirmation) },
	AuthStatusKey:                          func() any { return new(AuthStatus) },
	AgentInfoRequestKey:                    func() any { return new(AgentInfoRequest) },
	AgentInfoResponseKey:                   func() any { return new(AgentInfoResponse) },
	AgentInfoEventKey:                      func() any { return new(AgentInfoEvent) },
	AgentStatusRequestKey:                  func() any { return new(AgentStatusRequest) },
	PresentationUrlAvailabilityRequestKey:  func() any { return new(PresentationUrlAvailabilityRequest) },
	PresentationUrlAvailabilityResponseKey: func() any { return new(PresentationUrlAvailabilityResponse) },
	PresentationUrlAvailabilityEventKey:    func() any { return new(PresentationUrlAvailabilityEvent) },
	PresentationStartRequestKey:            func() any { return new(PresentationStartRequest) },
	PresentationStartResponseKey:           func() any { return new(PresentationStartResponse) },
	PresentationTerminationRequestKey:      func() any { return new(PresentationTerminationRequest) },
	PresentationTerminationResponseKey:     func() any { return new(PresentationTerminationResponse) },
	PresentationTerminationEventKey:        func() any { return new(PresentationTerminationEvent) },
	PresentationConnectionOpenRequestKey:   func() any { return new(PresentationConnectionOpenRequest) },
	PresentationConnectionOpenResponseKey:  func() any { return new(PresentationConnectionOpenResponse) },
	PresentationConnectionCloseEventKey:    func() any { return new(PresentationConnectionCloseEvent) },
	PresentationChangeEventKey:             func() any { return new(PresentationChangeEvent) },
	PresentationConnectionMessageKey:       func() any { return new(PresentationConnectionMessage) },
	RemotePlaybackAvailabilityRequestKey:   func() any { return new(RemotePlaybackAvailabilityRequest) },
	RemotePlaybackAvailabilityResponseKey:  func() any { return new(RemotePlaybackAvailabilityResponse) },
	RemotePlaybackAvailabilityEventKey:     func() any { return new(RemotePlaybackAvailabilityEvent) },
	RemotePlaybackStartRequestKey:          func() any { return new(RemotePlaybackStartRequest) },
	RemotePlaybackStartResponseKey:         func() any { return new(RemotePlaybackStartResponse) },
	RemotePlaybackTerminationRequestKey:    func() any { return new(RemotePlaybackTerminationRequest) },
	RemotePlaybackTerminationResponseKey:   func() any { return new(RemotePlaybackTerminationResponse) },
	RemotePlaybackTerminationEventKey:      func() any { return new(RemotePlaybackTerminationEvent) },
	RemotePlaybackModifyRequestKey:         func() any { return new(RemotePlaybackModifyRequest) },
	RemotePlaybackModifyResponseKey:        func() any { return new(RemotePlaybackModifyResponse) },
	RemotePlaybackStateEventKey:            func() any { return new(RemotePlaybackStateEvent) },
	AudioFrameKey:                          func() any { return new(AudioFrame) },
	VideoFrameKey:                          func() any { return new(VideoFrame) },
	DataFrameKey:                           func() any { return new(DataFrame) },
	StreamingCapabilitiesRequestKey:        func() any { return new(StreamingCapabilitiesRequest) },
	StreamingCapabilitiesResponseKey:       func() any { return new(StreamingCapabilitiesResponse) },
	StreamingSessionStartRequestKey:        func() any { return new(StreamingSessionStartRequest) },
	StreamingSessionStartResponseKey:       func() any { return new(StreamingSessionStartResponse) },
	StreamingSessionModifyRequestKey:       func() any { return new(StreamingSessionModifyRequest) },
	StreamingSessionModifyResponseKey:      func() any { return new(StreamingSessionModifyResponse) },
	StreamingSessionTerminateRequestKey:    func() any { return new(StreamingSessionTerminateRequest) },
	StreamingSessionTerminateResponseKey:   func() any { return new(StreamingSessionTerminateResponse) },
	StreamingSessionTerminateEventKey:      func() any { return new(StreamingSessionTerminateEvent) },
	StreamingSessionSenderStatsEventKey:    func() any { return new(StreamingSessionSenderStatsEvent) },
	StreamingSessionReceiverStatsEventKey:  func() any { return new(StreamingSessionReceiverStatsEvent) },
}

func GetVal(key TypeKey) any {
	return typeMap[key]()
}

type PskInputMethod uint32

const (
	Numeric PskInputMethod = iota
	QrCode
)

type AuthSpake2PskStatus uint

const (
	PskNeedsPresentation AuthSpake2PskStatus = iota
	PskShown
	PskInput
)

const AuthCapabilitiesKey TypeKey = 1001

type AuthCapabilities struct {
	PskEaseOfInput      uint32           `cbor:"0,keyasint"`
	PskInputMethods     []PskInputMethod `cbor:"1,keyasint"`
	PskMinBitsOfEntropy uint32           `cbor:"2,keyasint"`
}

const AuthSpake2HandshakeKey TypeKey = 1005

type AuthSpake2Handshake struct {
	InitiationToken AuthInitiationToken `cbor:"0,keyasint"`
	PskStatus       AuthSpake2PskStatus `cbor:"1,keyasint"`
	PublicValue     []byte              `cbor:"2,keyasint"`
}

type AuthInitiationToken struct {
	Token *string `cbor:"0,keyasint,omitempty"`
}

const AuthSpake2ConfirmationKey TypeKey = 1003

type AuthSpake2Confirmation struct {
	Bytes []byte `cbor:"0,keyasint"`
}

const AuthStatusKey TypeKey = 1004

type AuthStatus struct {
	Result AuthStatusResult `cbor:"0,keyasint"`
}

type AuthStatusResult uint32

const (
	Authenticated AuthStatusResult = iota
	UnknownAuthError
	AuthTimeout
	SecretUnknown
	ValidationTookTooLong
	ProofInvalid
)

type RequestId uint32

type Request struct {
	RequestId RequestId `cbor:"0,keyasint"`
}

func (r Request) GetId() RequestId {
	return r.RequestId
}

type OspRequest interface {
	GetId() RequestId
}

type ResponseId uint32

type Response struct {
	ResponseId ResponseId `cbor:"0,keyasint"`
}

func (r *Response) GetId() ResponseId {
	return r.ResponseId
}

type OspResponse interface {
	GetId() ResponseId
}

const AgentInfoRequestKey TypeKey = 10

type AgentInfoRequest struct {
	Request
}

const AgentInfoResponseKey TypeKey = 11

type AgentInfoResponse struct {
	Response
	AgentInfo AgentInfo `cbor:"1,keyasint"`
}

const AgentInfoEventKey = 120

type AgentInfoEvent struct {
	AgentInfo AgentInfo `cbor:"0,keyasint"`
}

const AgentStatusRequestKey TypeKey = 12

type AgentStatusRequest struct {
	Request
	Status *Status `cbor:"1,keyasint,omitempty"`
}

const AgentStatusResponseKey TypeKey = 13

type AgentStatusResponse struct {
	Response
	Status *Status `cbor:"1,keyasint,omitempty"`
}

type Status struct {
	Status string `cbor:"0,keyasint"`
}

type MediaTimeline float64

type Microseconds uint64

type EpochTime int64

type MediaTimelineRange struct {
	_     struct{} `cbor:",toarray"`
	Start MediaTimeline
	End   MediaTimeline
}

type WatchId uint32

const PresentationUrlAvailabilityRequestKey TypeKey = 14

type PresentationUrlAvailabilityRequest struct {
	Request
	Urls          []string     `cbor:"1,keyasint"`
	WatchDuration Microseconds `cbor:"2,keyasint"`
	WatchId       WatchId      `cbor:"3,keyasint"`
}

const PresentationUrlAvailabilityResponseKey TypeKey = 15

type PresentationUrlAvailabilityResponse struct {
	Response
	UrlAvailibilities []UrlAvailability `cbor:"1,keyasint"`
}

const PresentationUrlAvailabilityEventKey TypeKey = 103

type PresentationUrlAvailabilityEvent struct {
	WatchId           WatchId           `cbor:"0,keyasint"`
	UrlAvailibilities []UrlAvailability `cbor:"1,keyasint"`
}

type UrlAvailability uint32

const (
	Available   UrlAvailability = 0
	Unavailable UrlAvailability = 1
	Invalid     UrlAvailability = 10
)

const PresentationStartRequestKey TypeKey = 104

type PresentationStartRequest struct {
	Request
	PresentationId string       `cbor:"1,keyasint"`
	Url            string       `cbor:"2,keyasint"`
	Headers        []HttpHeader `cbor:"3,keyasint"`
}

type HttpHeader struct {
	_     struct{} `cbor:",toarray"`
	Key   string
	Value string
}

const PresentationStartResponseKey TypeKey = 105

type PresentationStartResponse struct {
	Response
	Result           Result  `cbor:"1,keyasint"`
	ConnectionId     uint32  `cbor:"2,keyasint"`
	HttpResponseCode *uint32 `cbor:"3,keyasint,omitempty"`
}

type PresentationTerminationSource uint32

const (
	Contoller     PresentationTerminationSource = 1
	Reciever      PresentationTerminationSource = 2
	UnknownSource PresentationTerminationSource = 255
)

type PresentationTerminationReason uint32

const (
	ApplicationRequest           PresentationTerminationReason = 1
	UserRequest                  PresentationTerminationReason = 2
	RecieverReplacedPresentation PresentationTerminationReason = 20
	ReceiverIdleTooLong          PresentationTerminationReason = 30
	RecieverAttemptedToNavigate  PresentationTerminationReason = 31
	ReceiverPoweringDown         PresentationTerminationReason = 100
	RecieverError                PresentationTerminationReason = 101
	UnknownReason                PresentationTerminationReason = 255
)

const PresentationTerminationRequestKey TypeKey = 106

type PresentationTerminationRequest struct {
	Request
	PresentationId string                        `cbor:"1,keyasint"`
	Reason         PresentationTerminationReason `cbor:"2,keyasint"`
}

const PresentationTerminationResponseKey TypeKey = 107

type PresentationTerminationResponse struct {
	Response
	Result Result `cbor:"1,keyasint"`
}

const PresentationTerminationEventKey TypeKey = 108

type PresentationTerminationEvent struct {
	PresentationId string                        `cbor:"0,keyasint"`
	Source         PresentationTerminationSource `cbor:"1,keyasint"`
	Reason         PresentationTerminationReason `cbor:"2,keyasint"`
}

const PresentationConnectionOpenRequestKey TypeKey = 109

type PresentationConnectionOpenRequest struct {
	Request
	PresentationId string `cbor:"1,keyasint"`
	Url            string `cbor:"2,keyasint"`
}

const PresentationConnectionOpenResponseKey TypeKey = 110

type PresentationConnectionOpenResponse struct {
	Response
	Result          Result `cbor:"1,keyasint"`
	ConnectionId    uint32 `cbor:"2,keyasint"`
	ConnectionCount uint32 `cbor:"3,keyasint"`
}

type PresentationConnectionCloseReason uint32

const (
	CloseMethodCalled                                PresentationConnectionCloseReason = 1
	ConnectionObjectDiscarded                        PresentationConnectionCloseReason = 10
	UnrecoverableErrorWhileSendingOrReceivingMessage PresentationConnectionCloseReason = 100
)

const PresentationConnectionCloseEventKey TypeKey = 113

type PresentationConnectionCloseEvent struct {
	ConnectionId    uint32                            `cbor:"0,keyasint"`
	Reason          PresentationConnectionCloseReason `cbor:"1,keyasint"`
	ErrorMessage    *string                           `cbor:"2,keyasint,omitempty"`
	ConnectionCount uint32                            `cbor:"3,keyasint"`
}

const PresentationChangeEventKey TypeKey = 121

type PresentationChangeEvent struct {
	PresentationId  string `cbor:"0,keyasint"`
	ConnectionCoutn uint32 `cbor:"1,keyasint"`
}

const PresentationConnectionMessageKey TypeKey = 16

type PresentationConnectionMessage struct {
	ConnectionId uint32 `cbor:"0,keyasint"`
	Message      []byte `cbor:"1,keyasint"`
}

type Result uint32

const (
	Success               Result = 1
	InvalidUrl            Result = 10
	InvalidPresentationId Result = 11
	Timeout               Result = 100
	TransientError        Result = 101
	PermanentError        Result = 102
	Terminating           Result = 103
	UnknownError          Result = 199
)

const RemotePlaybackAvailabilityRequestKey TypeKey = 17

type RemotePlaybackAvailabilityRequest struct {
	Request
	Sources       []RemotePlaybackSource `cbor:"1,keyasint"`
	WatchDuration Microseconds           `cbor:"2,keyasint"`
	WatchId       WatchId                `cbor:"3,keyasint"`
}

const RemotePlaybackAvailabilityResponseKey TypeKey = 18

type RemotePlaybackAvailabilityResponse struct {
	Response
	UrlAvailabilities []UrlAvailability `cbor:"1,keyasint"`
}

const RemotePlaybackAvailabilityEventKey TypeKey = 114

type RemotePlaybackAvailabilityEvent struct {
	WatchId           WatchId           `cbor:"0,keyasint"`
	UrlAvailabilities []UrlAvailability `cbor:"1,keyasint"`
}

const RemotePlaybackStartRequestKey TypeKey = 115

type RemotePlaybackStartRequest struct {
	Request
	RemotePlaybackId RemotePlaybackId                    `cbor:"1,keyasint"`
	Sources          *[]RemotePlaybackSource             `cbor:"2,keyasint,omitempty"`
	TextTrackUrls    *[]string                           `cbor:"3,keyasint,omitempty"`
	Headers          *[]HttpHeader                       `cbor:"4,keyasint,omitempty"`
	Controls         *RemotePlaybackControls             `cbor:"5,keyasint,omitempty"`
	Remoting         *StreamingSessionStartRequestParams `cbor:"6,keyasint,omitempty"`
}

type RemotePlaybackSource struct {
	Url              string `cbor:"0,keyasint"`
	ExtendedMimeType string `cbor:"1,keyasint"`
}

const RemotePlaybackStartResponseKey TypeKey = 116

type RemotePlaybackStartResponse struct {
	Response
	State    *RemotePlaybackState                 `cbor:"1,keyasint,omitempty"`
	Remoting *StreamingSessionStartResponseParams `cbor:"2,keyasint,omitempty"`
}

const RemotePlaybackTerminationRequestKey TypeKey = 117

type RemotePlaybackTerminationRequest struct {
	Request
	RemotePlaybackId RemotePlaybackId                       `cbor:"1,keyasint"`
	Reason           RemotePlaybackTerminationRequestReason `cbor:"2,keyasint"`
}

type RemotePlaybackTerminationRequestReason uint32

const (
	UserTerminatedViaController RemotePlaybackTerminationRequestReason = 11
	UnknownTerminationReason    RemotePlaybackTerminationRequestReason = 255
)

const RemotePlaybackTerminationResponseKey TypeKey = 118

type RemotePlaybackTerminationResponse struct {
	Response
	Result Result `cbor:"1,keyasint"`
}

const RemotePlaybackTerminationEventKey TypeKey = 119

type RemotePlaybackTerminationEvent struct {
	RemotePlaybackId RemotePlaybackId `cbor:"0,keyasint"`
	Reason           RemotePlaybackTerminationEventReason
}

type RemotePlaybackTerminationEventReason uint32

const (
	ReceiverCalledTerminate                     RemotePlaybackTerminationEventReason = 1
	UserTerminatedViaReceiver                   RemotePlaybackTerminationEventReason = 2
	ReceiverIdleTooLongRemotePlayback           RemotePlaybackTerminationEventReason = 30
	ReceiverPoweringDownRemotePlayback          RemotePlaybackTerminationEventReason = 100
	ReceiverCrashed                             RemotePlaybackTerminationEventReason = 101
	UnknownRemotePlaybackTerminationEventReason RemotePlaybackTerminationEventReason = 255
)

const RemotePlaybackModifyRequestKey TypeKey = 19

type RemotePlaybackModifyRequest struct {
	Request
	RemotePlaybackId RemotePlaybackId       `cbor:"1,keyasint"`
	Controls         RemotePlaybackControls `cbor:"2,keyasint"`
}

const RemotePlaybackModifyResponseKey TypeKey = 20

type RemotePlaybackModifyResponse struct {
	Response
	Result Result               `cbor:"1,keyasint"`
	State  *RemotePlaybackState `cbor:"2,keyasint,omitempty"`
}

const RemotePlaybackStateEventKey TypeKey = 21

type RemotePlaybackStateEvent struct {
	RemotePlaybackId RemotePlaybackId    `cbor:"0,keyasint"`
	State            RemotePlaybackState `cbor:"1,keyasint"`
}

type RemotePlaybackId uint32

type RemotePlaybackControls struct {
	Source               *RemotePlaybackSource `cbor:"0,keyasint,omitempty"`
	Preload              *PreloadControls      `cbor:"1,keyasint,omitempty"`
	Loop                 *bool                 `cbor:"2,keyasint,omitempty"`
	Paused               *bool                 `cbor:"3,keyasint,omitempty"`
	Muted                *bool                 `cbor:"4,keyasint,omitempty"`
	Volume               *float64              `cbor:"5,keyasint,omitempty"`
	Seek                 *MediaTimeline        `cbor:"6,keyasint,omitempty"`
	FastSeek             *MediaTimeline        `cbor:"7,keyasint,omitempty"`
	PlaybackRate         *float64              `cbor:"8,keyasint,omitempty"`
	Poster               *string               `cbor:"9,keyasint,omitempty"`
	EnabledAudioTrackIds *[]string             `cbor:"10,keyasint,omitempty"`
	SelectedVideoTrackId *string               `cbor:"11,keyasint,omitempty"`
	AddedTextTracks      *[]AddedTextTrack     `cbor:"12,keyasint,omitempty"`
	ChangedTextTracks    *[]ChangedTextTrack   `cbor:"13,keyasint,omitempty"`
}

type RemotePlaybackState struct {
	Supports           *RemotePlaybackSupports `cbor:"0,keyasint,omitempty"`
	Source             *RemotePlaybackSource   `cbor:"1,keyasint,omitempty"`
	Loading            *RemotePlaybackLoading  `cbor:"2,keyasint,omitempty"`
	Loaded             *RemotePlaybackLoaded   `cbor:"3,keyasint,omitempty"`
	Error              *MediaError             `cbor:"4,keyasint,omitempty"`
	Epoch              *EpochTime              `cbor:"5,keyasint,omitempty"`
	Duration           *MediaTimeline          `cbor:"6,keyasint,omitempty"`
	BufferedTimeRanges *[]MediaTimelineRange   `cbor:"7,keyasint,omitempty"`
	SeekableTimeRanges *[]MediaTimelineRange   `cbor:"8,keyasint,omitempty"`
	PlayedTimeRanges   *[]MediaTimelineRange   `cbor:"9,keyasint,omitempty"`
	Position           *MediaTimeline          `cbor:"10,keyasint,omitempty"`
	PlaybackRate       *float64                `cbor:"11,keyasint,omitempty"`
	Paused             *bool                   `cbor:"12,keyasint,omitempty"`
	Seeking            *bool                   `cbor:"13,keyasint,omitempty"`
	Stalled            *bool                   `cbor:"14,keyasint,omitempty"`
	Ended              *bool                   `cbor:"15,keyasint,omitempty"`
	Volume             *float64                `cbor:"16,keyasint,omitempty"`
	Muted              *bool                   `cbor:"17,keyasint,omitempty"`
	Resolution         *VideoResolution        `cbor:"18,keyasint,omitempty"`
	AudioTracks        *[]AudioTrackState      `cbor:"19,keyasint,omitempty"`
	VideoTracks        *[]VideoTrackState      `cbor:"20,keyasint,omitempty"`
	TextTracks         *[]TextTrackState       `cbor:"21,keyasint,omitempty"`
}

type RemotePlaybackLoading uint32

const (
	Empty RemotePlaybackLoading = iota
	Idle
	Loading
	NoSource
)

type RemotePlaybackLoaded uint32

const (
	Nothing RemotePlaybackLoaded = iota
	MetadataLoaded
	Current
	Future
	Enough
)

type RemotePlaybackSupports struct {
	Rate           bool `cbor:"0,keyasint"`
	Preload        bool `cbor:"1,keyasint"`
	Poster         bool `cbor:"2,keyasint"`
	AddedTextTrack bool `cbor:"3,keyasint"`
	AddedCues      bool `cbor:"4,keyasint"`
}

type PreloadControls uint32

const (
	None             PreloadControls = 0
	MetadataControls PreloadControls = 1
	Auto             PreloadControls = 2
)

type AddedTextTrack struct {
	Kind     TextTrackKind `cbor:"0,keyasint"`
	Label    *string       `cbor:"1,keyasint,omitempty"`
	Language *string       `cbor:"2,keyasint,omitempty"`
}

type TextTrackKind uint32

const (
	_ TextTrackKind = iota
	Subtitles
	Captions
	Descriptions
	Chapters
	MetadataTextTrack
)

type ChangedTextTrack struct {
	Id            string          `cbor:"0,keyasint"`
	Mode          TextTrackMode   `cbor:"1,keyasint"`
	AddedCues     *[]TextTrackCue `cbor:"2,keyasint,omitempty"`
	RemovedCueIds *[]string       `cbor:"3,keyasint,omitempty"`
}

type TextTrackMode uint32

const (
	_ TextTrackMode = iota
	Disabled
	Showing
	Hidden
)

type TextTrackCue struct {
	Id    string             `cbor:"0,keyasint"`
	Range MediaTimelineRange `cbor:"1,keyasint"`
	Text  string             `cbor:"2,keyasint"`
}

type MediaSyncTime struct {
	_     struct{} `cbor:",toarray"`
	Value uint32
	Scale uint32
}

type MediaError struct {
	_       struct{} `cbor:",toarray"`
	Code    MediaErrorCode
	Message string
}

type MediaErrorCode uint32

const (
	_ MediaErrorCode = iota
	UserAborted
	NetworkError
	DecodeError
	SourceNotSupported
	UnknownMediaError
)

type TrackState struct {
	Id       string `cbor:"0,keyasint"`
	Label    string `cbor:"1,keyasint"`
	Language string `cbor:"2,keyasint"`
}

type AudioTrackState struct {
	TrackState
	Enabled bool `cbor:"3,keyasint"`
}

type VideoTrackState struct {
	TrackState
	Selected bool `cbor:"3,keyasint"`
}

type TextTrackState struct {
	TrackState
	Mode TextTrackMode `cbor:"3,keyasint"`
}

const AudioFrameKey TypeKey = 22

type AudioFrame struct {
	_          struct{} `cbor:",toarray"`
	EncodingId uint32
	StartTime  uint64
	Payload    []byte
	Optional   AudioFrameOptional `cbor:",omitempty"`
}

type AudioFrameOptional struct {
	Duration *uint64        `cbor:"0,keyasint,omitempty"`
	SyncTime *MediaSyncTime `cbor:"1,keyasint,omitempty"`
}

const VideoFrameKey TypeKey = 23

type VideoFrame struct {
	EncodingId     uint32         `cbor:"0,keyasint"`
	SequenceNumber uint64         `cbor:"1,keyasint"`
	DependsOn      *[]int64       `cbor:"2,keyasint,omitempty"`
	StartTime      uint64         `cbor:"3,keyasint"`
	Duration       *uint64        `cbor:"4,keyasint,omitempty"`
	Payload        []byte         `cbor:"5,keyasint"`
	VideoRotation  *uint32        `cbor:"6,keyasint,omitempty"`
	SyncTime       *MediaSyncTime `cbor:"7,keyasint,omitempty"`
}

const DataFrameKey TypeKey = 24

type DataFrame struct {
	EncodingId     uint32         `cbor:"0,keyasint"`
	SequenceNumber *uint64        `cbor:"1,keyasint,omitempty"`
	StartTime      *uint64        `cbor:"2,keyasint,omitempty"`
	Duration       *uint64        `cbor:"3,keyasint,omitempty"`
	Payload        []byte         `cbor:"4,keyasint"`
	SyncTime       *MediaSyncTime `cbor:"5,keyasint,omitempty"`
}

type Ratio struct {
	_          struct{} `cbor:",toarray"`
	Antecedent uint64
	Consequent uint64
}

const StreamingCapabilitiesRequestKey TypeKey = 122

type StreamingCapabilitiesRequest struct {
	Request
}

const StreamingCapabilitiesResponseKey TypeKey = 123

type StreamingCapabilitiesResponse struct {
	Response
	StreamingCapabilities StreamingCapabilities `cbor:"1,keyasint"`
}

type StreamingCapabilities struct {
	ReceiveAudio []ReceiveAudioCapability `cbor:"0,keyasint"`
	ReceiveVideo []ReceiveVideoCapability `cbor:"1,keyasint"`
	ReceiveData  []ReceiveDataCapability  `cbor:"2,keyasint"`
}

type Format struct {
	CodecName string `cbor:"0,keyasint"`
}

type ReceiveAudioCapability struct {
	Codec            Format  `cbor:"0,keyasint"`
	MaxAudioChannels *uint32 `cbor:"1,keyasint,omitempty"`
	MinBitRate       *uint32 `cbor:"2,keyasint,omitempty"`
}

type VideoResolution struct {
	Height uint32 `cbor:"0,keyasint"`
	Width  uint32 `cbor:"1,keyasint"`
}

type VideoHdrFormat struct {
	TransferFunction string  `cbor:"0,keyasint"`
	HdrMetadata      *string `cbor:"1,keyasint,omitempty"`
}

type ReceiveVideoCapability struct {
	Codec              Format             `cbor:"0,keyasint"`
	MaxResolution      *VideoResolution   `cbor:"1,keyasint,omitempty"`
	MaxFramesPerSecond *Ratio             `cbor:"2,keyasint,omitempty"`
	MaxPixelsPerSecond *uint32            `cbor:"3,keyasint,omitempty"`
	MaxBitRate         *uint32            `cbor:"4,keyasint,omitempty"`
	AspectRatio        *Ratio             `cbor:"5,keyasint,omitempty"`
	ColorGamut         *string            `cbor:"6,keyasint,omitempty"`
	NativeResolutions  *[]VideoResolution `cbor:"7,keyasint,omitempty"`
	SupportsScaling    *bool              `cbor:"8,keyasint,omitempty"`
	SupportsRotation   *bool              `cbor:"9,keyasint,omitempty"`
	HdrFormats         *[]VideoHdrFormat  `cbor:"10,keyasint,omitempty"`
}

type ReceiveDataCapability struct {
	DataType Format `cbor:"0,keyasint"`
}

const StreamingSessionStartRequestKey TypeKey = 124

type StreamingSessionStartRequest struct {
	Request
	StreamingSessionStartRequestParams
}

const StreamingSessionStartResponseKey TypeKey = 125

type StreamingSessionStartResponse struct {
	Response
	StreamingSessionStartResponseParams
}

type StreamingSessionStartRequestParams struct {
	StreamingSessionId   uint32             `cbor:"1,keyasint"`
	StreamOffers         []MediaStreamOffer `cbor:"2,keyasint"`
	DesiredStatsInterval Microseconds       `cbor:"3,keyasint"`
}

const StreamingSessionModifyRequestKey TypeKey = 126

type StreamingSessionModifyRequest struct {
	Request
	StreamingSessionModifyRequestParams
}

type StreamingSessionStartResponseParams struct {
	Result               Result               `cbor:"1,keyasint"`
	StreamRequests       []MediaStreamRequest `cbor:"2,keyasint"`
	DesiredStatsInterval Microseconds         `cbor:"3,keyasint"`
}

type StreamingSessionModifyRequestParams struct {
	StreamingSessionId uint32               `cbor:"1,keyasint"`
	StreamRequests     []MediaStreamRequest `cbor:"2,keyasint"`
}

const StreamingSessionModifyResponseKey TypeKey = 127

type StreamingSessionModifyResponse struct {
	Response
	Result Result `cbor:"1,keyasint"`
}

const StreamingSessionTerminateRequestKey TypeKey = 128

type StreamingSessionTerminateRequest struct {
	Request
	StreamingSessionId uint32 `cbor:"1,keyasint"`
}

const StreamingSessionTerminateResponseKey TypeKey = 129

type StreamingSessionTerminateResponse struct {
	Response
}

const StreamingSessionTerminateEventKey TypeKey = 130

type StreamingSessionTerminateEvent struct {
	StreamingSessionId uint32 `cbor:"0,keyasint"`
}

type MediaStreamOffer struct {
	MediaStreamId uint32                `cbor:"0,keyasint"`
	DisplayName   *string               `cbor:"1,keyasint,omitempty"`
	Audio         *[]AudioEncodingOffer `cbor:"2,keyasint,omitempty"`
	Video         *[]VideoEncodingOffer `cbor:"3,keyasint,omitempty"`
	Data          *[]DataEncodingOffer  `cbor:"4,keyasint,omitempty"`
}

type MediaStreamRequest struct {
	MediaStreamId uint32                `cbor:"0,keyasint"`
	Audio         *AudioEncodingRequest `cbor:"1,keyasint,omitempty"`
	Video         *VideoEncodingRequest `cbor:"2,keyasint,omitempty"`
	Data          *DataEncodingRequest  `cbor:"3,keyasint,omitempty"`
}

type AudioEncodingOffer struct {
	EncodingId      uint32  `cbor:"0,keyasint"`
	CodecName       string  `cbor:"1,keyasint"`
	TimeScale       uint32  `cbor:"2,keyasint"`
	DefaultDuration *uint32 `cbor:"3,keyasint,omitempty"`
}

type VideoEncodingOffer struct {
	EncodingId      uint32         `cbor:"0,keyasint"`
	CodecName       string         `cbor:"1,keyasint"`
	TimeScale       uint32         `cbor:"2,keyasint"`
	DefaultDuration *uint32        `cbor:"3,keyasint,omitempty"`
	DefaultRotation *VideoRotation `cbor:"4,keyasint,omitempty"`
}

type DataEncodingOffer struct {
	EncodingId      uint32  `cbor:"0,keyasint"`
	DataTypeName    Format  `cbor:"1,keyasint"`
	TimeScale       uint32  `cbor:"2,keyasint"`
	DefaultDuration *uint32 `cbor:"3,keyasint,omitempty"`
}

type AudioEncodingRequest struct {
	EncodingId uint32 `cbor:"0,keyasint"`
}

type VideoEncodingRequest struct {
	EncodingId         uint32           `cbor:"0,keyasint"`
	TargetResolution   *VideoResolution `cbor:"1,keyasint,omitempty"`
	MaxFramesPerSecond *Ratio           `cbor:"2,keyasint,omitempty"`
}

type DataEncodingRequest struct {
	EncodingId uint32 `cbor:"0,keyasint"`
}

type VideoRotation uint32

const (
	//degrees clockwise
	VideoRotation0 VideoRotation = iota
	VideoRotation90
	VideoRotation180
	VideoRotation270
)

type SenderStatsAudio struct {
	EncodingId            uint32        `cbor:"0,keyasint"`
	CumulativeSentFrames  *uint32       `cbor:"1,keyasint,omitempty"`
	CumulativeEncodeDelay *Microseconds `cbor:"2,keyasint,omitempty"`
}

type SenderStatsVideo struct {
	EncodingId              uint32        `cbor:"0,keyasint"`
	CumulativeSentDuration  *Microseconds `cbor:"1,keyasint,omitempty"`
	CummulativeEncodeDelay  *Microseconds `cbor:"2,keyasint,omitempty"`
	CumulativeDroppedFrames *uint32       `cbor:"3,keyasint,omitempty"`
}

const StreamingSessionSenderStatsEventKey TypeKey = 131

type StreamingSessionSenderStatsEvent struct {
	StreamingSessionId uint32              `cbor:"0,keyasint"`
	SystemTime         Microseconds        `cbor:"1,keyasint"`
	Audio              *[]SenderStatsAudio `cbor:"2,keyasint,omitempty"`
	Video              *[]SenderStatsVideo `cbor:"3,keyasint,omitempty"`
}

type StreamingBufferStatus uint32

const (
	EnoughData StreamingBufferStatus = iota
	InsufficientData
	TooMuchData
)

type ReceiverStatsAudio struct {
	EncodingId                 uint32                 `cbor:"0,keyasint"`
	CumulativeReceivedDuration *Microseconds          `cbor:"1,keyasint,omitempty"`
	CumulativeLostDuration     *Microseconds          `cbor:"2,keyasint,omitempty"`
	CumulativeBufferDelay      *Microseconds          `cbor:"3,keyasint,omitempty"`
	CumulativeDecodeDelay      *Microseconds          `cbor:"4,keyasint,omitempty"`
	RemoteBufferStatus         *StreamingBufferStatus `cbor:"5,keyasint,omitempty"`
}

type ReceiverStatsVideo struct {
	EncodingId              uint32                 `cbor:"0,keyasint"`
	CumulativeDecodedFrames *uint32                `cbor:"1,keyasint,omitempty"`
	CumulativeLostFrames    *uint32                `cbor:"2,keyasint,omitempty"`
	CumulativeBufferDelay   *Microseconds          `cbor:"3,keyasint,omitempty"`
	CumulativeDecodeDelay   *Microseconds          `cbor:"4,keyasint,omitempty"`
	RemoteBufferStatus      *StreamingBufferStatus `cbor:"5,keyasint,omitempty"`
}

const StreamingSessionReceiverStatsEventKey TypeKey = 132

type StreamingSessionReceiverStatsEvent struct {
	StreamingSessionId uint32                `cbor:"0,keyasint"`
	SystemTime         Microseconds          `cbor:"1,keyasint"`
	Audio              *[]ReceiverStatsAudio `cbor:"2,keyasint,omitempty"`
	Video              *[]ReceiverStatsVideo `cbor:"3,keyasint,omitempty"`
}

type AgentCapability uint32

const (
	_ AgentCapability = iota
	RecieveAudio
	RecieveVideo
	RecievePresentation
	ControlPresentation
	RecieveRemotePlayback
	ControlRemotePlayback
	RecieveStreaming
	SendStreaming
)

type AgentInfo struct {
	DisplayName  string            `cbor:"0,keyasint"`
	ModelName    string            `cbor:"1,keyasint"`
	Capabilities []AgentCapability `cbor:"2,keyasint"`
	StateToken   string            `cbor:"3,keyasint"`
	Locales      []string          `cbor:"4,keyasint"`
}
