package datasync

import (
	"context"
	"crypto/ecdsa"
	"errors"

	"github.com/golang/protobuf/proto"
	"github.com/vacp2p/mvds/protobuf"
	"github.com/vacp2p/mvds/state"
	"github.com/vacp2p/mvds/transport"
	"go.uber.org/zap"

	datasyncpeer "github.com/status-im/status-go/protocol/datasync/peer"
)

var errNotInitialized = errors.New("Datasync transport not initialized")

// payloadTagSize is the tag size for the protobuf.Payload message which is number of fields * 2 bytes
var payloadTagSize = 14

// timestampPayloadSize is the maximum size in bytes for the timestamp field (uint64)
var timestampPayloadSize = 10

type NodeTransport struct {
	packets        chan transport.Packet
	logger         *zap.Logger
	maxMessageSize uint32
	dispatch       func(context.Context, *ecdsa.PublicKey, []byte, *protobuf.Payload) error
}

func NewNodeTransport() *NodeTransport {
	return &NodeTransport{
		packets: make(chan transport.Packet),
	}
}

func (t *NodeTransport) Init(dispatch func(context.Context, *ecdsa.PublicKey, []byte, *protobuf.Payload) error, maxMessageSize uint32, logger *zap.Logger) {
	t.dispatch = dispatch
	t.maxMessageSize = maxMessageSize
	t.logger = logger
}

func (t *NodeTransport) AddPacket(p transport.Packet) {
	t.packets <- p
}

func (t *NodeTransport) Watch() transport.Packet {
	return <-t.packets
}

func (t *NodeTransport) Send(_ state.PeerID, peer state.PeerID, payload protobuf.Payload) error {
	var lastError error
	if t.dispatch == nil {
		return errNotInitialized
	}

	t.logger.Info("sending datasync message", zap.Int("max-message-size", int(t.maxMessageSize)))

	payloads := splitPayloadInBatches(&payload, int(t.maxMessageSize), t.logger)
	for _, payload := range payloads {

		data, err := proto.Marshal(payload)
		if err != nil {
			return err
		}

		publicKey, err := datasyncpeer.IDToPublicKey(peer)
		if err != nil {
			return err
		}
		err = t.dispatch(context.Background(), publicKey, data, payload)
		if err != nil {
			lastError = err
			t.logger.Error("failed to send message", zap.Error(err))
			continue
		}
	}
	return lastError
}

func splitPayloadInBatches(payload *protobuf.Payload, maxSizeBytes int, logger *zap.Logger) []*protobuf.Payload {
	newPayload := &protobuf.Payload{}
	var response []*protobuf.Payload
	currentSize := payloadTagSize

	// this is not going to be 100% accurate, but should be fine in most cases, faster
	// than using proto.Size
	for _, ack := range payload.Acks {
		logger.Info("Checking acks", zap.Int("size", currentSize))
		if len(ack)+currentSize+1 > maxSizeBytes {
			// We check if it's valid as it might be that the initial message
			// is too big, in this case we still batch it
			if newPayload.IsValid() {
				response = append(response, newPayload)
			}
			newPayload = &protobuf.Payload{Acks: [][]byte{ack}}
			currentSize = len(ack) + payloadTagSize + 1
		} else {
			newPayload.Acks = append(newPayload.Acks, ack)
			currentSize += len(ack)
		}
	}

	for _, offer := range payload.Offers {
		logger.Info("Checking offers", zap.Int("size", currentSize))
		if len(offer)+currentSize+1 > maxSizeBytes {
			if newPayload.IsValid() {
				response = append(response, newPayload)
			}
			newPayload = &protobuf.Payload{Offers: [][]byte{offer}}
			currentSize = len(offer) + payloadTagSize + 1
		} else {
			newPayload.Offers = append(newPayload.Offers, offer)
			currentSize += len(offer)
		}
	}

	for _, request := range payload.Requests {
		logger.Info("Checking requests", zap.Int("size", currentSize))
		if len(request)+currentSize+1 > maxSizeBytes {
			if newPayload.IsValid() {
				response = append(response, newPayload)
			}
			newPayload = &protobuf.Payload{Requests: [][]byte{request}}
			currentSize = len(request) + payloadTagSize + 1
		} else {
			newPayload.Requests = append(newPayload.Requests, request)
			currentSize += len(request)
		}
	}

	for _, message := range payload.Messages {
		logger.Info("Checking messages", zap.Int("size", currentSize), zap.Int("message-size", len(message.Body)))
		// We add the body size, the length field for payload, the length field for group id,
		// the length of timestamp, body and groupid
		if currentSize+1+1+timestampPayloadSize+len(message.Body)+len(message.GroupId) > maxSizeBytes {
			logger.Info("splitting message")
			if newPayload.IsValid() {
				response = append(response, newPayload)
			}
			newPayload = &protobuf.Payload{Messages: []*protobuf.Message{message}}
			currentSize = timestampPayloadSize + len(message.Body) + len(message.GroupId) + payloadTagSize + 1 + 1
		} else {
			newPayload.Messages = append(newPayload.Messages, message)
			currentSize += len(message.Body) + len(message.GroupId) + timestampPayloadSize
		}
	}

	if newPayload.IsValid() {
		response = append(response, newPayload)
	}
	logger.Info("split messages", zap.Int("count", len(response)))
	return response
}

// CalculateSendTime calculates the next epoch
// at which a message should be sent.
func CalculateSendTime(count uint64, time int64) int64 {
	return time + int64(count*2) // @todo this should match that time is increased by whisper periods, aka we only retransmit the first time when a message has expired.
}
