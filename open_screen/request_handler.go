package open_screen

import (
	"errors"
	"sync"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/quic-go/quic-go"
)

type RequestHandler struct {
	requests   map[RequestId]chan []byte
	requestsMu sync.RWMutex
}

func NewRequestHandler() *RequestHandler {
	return &RequestHandler{
		requests: make(map[RequestId]chan []byte),
	}
}

func (r *RequestHandler) SendRequestAndWait(conn *quic.Conn, request OspRequest, response any, key TypeKey) error {

	msg, err := EncodeMessageWithKey(request, key)
	if err != nil {
		return err
	}

	err = SendMessage(conn, msg)
	if err != nil {
		return err
	}

	rspChan, err := r.registerRequest(request)
	if err != nil {
		return err
	}
	rsp := <-rspChan
	return cbor.Unmarshal(rsp, response)
}

var ErrRequestTimeout = errors.New("request timed out")

func (r *RequestHandler) SendRequestWithTimeout(conn *quic.Conn, request OspRequest, response any, key TypeKey, timeout time.Duration) error {
	retChan := make(chan error)
	go func() {
		err := r.SendRequestAndWait(conn, request, response, key)
		retChan <- err
	}()
	select {
	case err := <-retChan:
		return err
	case <-time.After(timeout):
		r.cancelRequest(request)
		return ErrRequestTimeout
	}
}

var errRequestExists = errors.New("request already exists")

func (r *RequestHandler) registerRequest(request OspRequest) (chan []byte, error) {
	r.requestsMu.RLock()
	if _, ok := r.requests[request.GetId()]; ok {
		r.requestsMu.RUnlock()
		return nil, errRequestExists
	}
	r.requestsMu.RUnlock()

	r.requestsMu.Lock()
	defer r.requestsMu.Unlock()
	rspChan := make(chan []byte)
	r.requests[request.GetId()] = rspChan
	return rspChan, nil
}

func (r *RequestHandler) cancelRequest(request OspRequest) {
	r.requestsMu.Lock()
	defer r.requestsMu.Unlock()
	delete(r.requests, request.GetId())
}

func (r *RequestHandler) HandleResponse(rsp []byte) {
	r.requestsMu.Lock()
	defer r.requestsMu.Unlock()
	response := Response{}
	cbor.Unmarshal(rsp, &response)
	rspChan, ok := r.requests[RequestId(response.GetId())]
	if !ok {
		return
	}
	delete(r.requests, RequestId(response.GetId()))
	rspChan <- rsp
}
