package open_screen

import (
	"errors"
	"log/slog"
)

type Handler func(data any)

type MessageHandler struct {
	handlers map[TypeKey]Handler
}

func NewMessageHandler() *MessageHandler {
	return &MessageHandler{
		handlers: make(map[TypeKey]Handler),
	}
}

var ErrHandlerNotFound = errors.New("handler not found")

func (m *MessageHandler) HandleData(key TypeKey, data any) error {
	slog.Debug("received data", "key", key)
	if handler, ok := m.handlers[TypeKey(key)]; ok {
		handler(data)
		return nil
	}
	return ErrHandlerNotFound
}

var ErrKeyAlreadyExists = errors.New("key already exists")

func (m *MessageHandler) AddHandler(key TypeKey, handler Handler) error {
	if _, ok := m.handlers[key]; ok {
		return ErrKeyAlreadyExists
	}
	m.handlers[key] = handler
	return nil
}

func (m *MessageHandler) ListenForKey(key TypeKey) (chan any, error) {
	retChan := make(chan any)
	err := m.AddHandler(key, func(data any) {
		retChan <- data
	})
	if err != nil {
		return nil, err
	}
	return retChan, nil
}

func (m *MessageHandler) AddRequestHandler(responseKey TypeKey, r *RequestHandler) error {
	return m.AddHandler(responseKey, func(data any) {
		r.HandleResponse(data)
	})
}
