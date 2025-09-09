package open_screen

import (
	"errors"
	"log/slog"
)

type Handler func([]byte)

type MessageHandler struct {
	handlers map[TypeKey]func([]byte)
}

func NewMessageHandler() *MessageHandler {
	return &MessageHandler{
		handlers: make(map[TypeKey]func([]byte)),
	}
}

var ErrHandlerNotFound = errors.New("handler not found")

func (m *MessageHandler) HandleMessage(msg []byte) error {
	key, msg := SeperateVint(msg)
	slog.Debug("received message", "key", key)
	if handler, ok := m.handlers[TypeKey(key)]; ok {
		handler(msg)
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

func (m *MessageHandler) ListenForKey(key TypeKey) (chan []byte, error) {
	retChan := make(chan []byte)
	err := m.AddHandler(key, func(b []byte) {
		retChan <- b
	})
	if err != nil {
		return nil, err
	}
	return retChan, nil
}

func (m *MessageHandler) AddRequestHandler(responseKey TypeKey, r *RequestHandler) error {
	return m.AddHandler(responseKey, func(b []byte) {
		r.HandleResponse(b)
	})
}
