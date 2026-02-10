package open_screen

import (
	"errors"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
)

type RequestHandler struct {
	requests   map[RequestId]chan any
	requestsMu sync.RWMutex
}

func NewRequestHandler() *RequestHandler {
	return &RequestHandler{
		requests: make(map[RequestId]chan any),
	}
}

func (r *RequestHandler) SendRequestAndWait(conn *quic.Conn, request OspRequest, key TypeKey) (any, error) {

	msg, err := EncodeMessageWithKey(request, key)
	if err != nil {
		return nil, err
	}

	err = SendMessage(conn, msg)
	if err != nil {
		return nil, err
	}

	dataChan, err := r.registerRequest(request)
	if err != nil {
		return nil, err
	}
	data := <-dataChan
	return data, nil
}

var ErrRequestTimeout = errors.New("request timed out")

type returnVal struct {
	data any
	err  error
}

func (r *RequestHandler) SendRequestWithTimeout(conn *quic.Conn, request OspRequest, key TypeKey, timeout time.Duration) (any, error) {
	retChan := make(chan returnVal)
	go func() {
		data, err := r.SendRequestAndWait(conn, request, key)
		retChan <- returnVal{data, err}
	}()
	select {
	case ret := <-retChan:
		return ret.data, ret.err
	case <-time.After(timeout):
		r.cancelRequest(request)
		return nil, ErrRequestTimeout
	}
}

var errRequestExists = errors.New("request already exists")

func (r *RequestHandler) registerRequest(request OspRequest) (chan any, error) {
	r.requestsMu.RLock()
	if _, ok := r.requests[request.GetId()]; ok {
		r.requestsMu.RUnlock()
		return nil, errRequestExists
	}
	r.requestsMu.RUnlock()

	r.requestsMu.Lock()
	defer r.requestsMu.Unlock()
	rspChan := make(chan any)
	r.requests[request.GetId()] = rspChan
	return rspChan, nil
}

func (r *RequestHandler) cancelRequest(request OspRequest) {
	r.requestsMu.Lock()
	defer r.requestsMu.Unlock()
	delete(r.requests, request.GetId())
}

func (r *RequestHandler) HandleResponse(data any) {
	r.requestsMu.Lock()
	defer r.requestsMu.Unlock()
	response := data.(OspResponse)
	rspChan, ok := r.requests[RequestId(response.GetId())]
	if !ok {
		return
	}
	delete(r.requests, RequestId(response.GetId()))
	rspChan <- data
}
