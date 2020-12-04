package protocol

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"math/big"
	"strings"
	"testing"

	"github.com/google/uuid"
	_ "github.com/mutecomm/go-sqlcipher" // require go-sqlcipher that overrides default implementation
	"github.com/stretchr/testify/suite"
	"go.uber.org/zap"

	gethbridge "github.com/status-im/status-go/eth-node/bridge/geth"
	coretypes "github.com/status-im/status-go/eth-node/core/types"
	"github.com/status-im/status-go/eth-node/crypto"
	"github.com/status-im/status-go/eth-node/types"
	"github.com/status-im/status-go/protocol/common"
	"github.com/status-im/status-go/protocol/protobuf"
	"github.com/status-im/status-go/protocol/tt"
	"github.com/status-im/status-go/waku"
)

func TestMessengerTransactionSuite(t *testing.T) {
	suite.Run(t, new(MessengerTransactionSuite))
}

type MessengerTransactionSuite struct {
	suite.Suite
	m          *Messenger        // main instance of Messenger
	privateKey *ecdsa.PrivateKey // private key for the main instance of Messenger
	// If one wants to send messages between different instances of Messenger,
	// a single waku service should be shared.
	shh    types.Waku
	logger *zap.Logger
}

func (s *MessengerTransactionSuite) newMessengerWithKey(shh types.Waku, privateKey *ecdsa.PrivateKey) *Messenger {
	options := []Option{
		WithCustomLogger(s.logger),
		WithMessagesPersistenceEnabled(),
		WithDatabaseConfig(":memory:", "some-key"),
		WithDatasync(),
	}

	m, err := NewMessenger(
		privateKey,
		&testNode{shh: shh},
		uuid.New().String(),
		options...,
	)
	s.Require().NoError(err)

	err = m.Init()
	s.Require().NoError(err)

	return m
}

func (s *MessengerTransactionSuite) SetupTest() {
	s.logger = tt.MustCreateTestLogger()

	config := waku.DefaultConfig
	config.MinimumAcceptedPoW = 0
	shh := waku.New(&config, s.logger)
	s.shh = gethbridge.NewGethWakuWrapper(shh)
	s.Require().NoError(shh.Start(nil))

	s.m = s.newMessenger(s.shh)
	s.privateKey = s.m.identity
	s.Require().NoError(s.m.Start())
}

func (s *MessengerTransactionSuite) newMessenger(shh types.Waku) *Messenger {
	privateKey, err := crypto.GenerateKey()
	s.Require().NoError(err)
	return s.newMessengerWithKey(shh, privateKey)
}

func (s *MessengerTransactionSuite) TestDeclineRequestAddressForTransaction() {
	value := testValue
	contract := testContract
	theirMessenger := s.newMessenger(s.shh)
	s.Require().NoError(theirMessenger.Start())
	theirPkString := types.EncodeHex(crypto.FromECDSAPub(&theirMessenger.identity.PublicKey))

	chat := CreateOneToOneChat(theirPkString, &theirMessenger.identity.PublicKey, s.m.transport)
	err := s.m.SaveChat(&chat)
	s.Require().NoError(err)

	myAddress := crypto.PubkeyToAddress(s.m.identity.PublicKey)

	response, err := s.m.RequestAddressForTransaction(context.Background(), theirPkString, myAddress.Hex(), value, contract)
	s.Require().NoError(err)
	s.Require().NotNil(response)
	s.Require().Len(response.Chats, 1)
	s.Require().Len(response.Messages, 1)

	senderMessage := response.Messages[0]
	s.Require().Equal(protobuf.ChatMessage_TRANSACTION_COMMAND, senderMessage.ContentType)
	initialCommandID := senderMessage.ID

	s.Require().Equal("Request address for transaction", senderMessage.Text)
	s.Require().NotNil(senderMessage.CommandParameters)
	s.Require().Equal(value, senderMessage.CommandParameters.Value)
	s.Require().Equal(contract, senderMessage.CommandParameters.Contract)
	s.Require().Equal(initialCommandID, senderMessage.CommandParameters.ID)
	s.Require().Equal(common.CommandStateRequestAddressForTransaction, senderMessage.CommandParameters.CommandState)

	// Wait for the message to reach its destination
	response, err = WaitOnMessengerResponse(
		theirMessenger,
		func(r *MessengerResponse) bool { return len(r.Messages) > 0 },
		"no messages",
	)
	s.Require().NoError(err)

	s.Require().NotNil(response)
	s.Require().Len(response.Chats, 1)
	s.Require().Len(response.Messages, 1)

	receiverMessage := response.Messages[0]
	s.Require().Equal(protobuf.ChatMessage_TRANSACTION_COMMAND, receiverMessage.ContentType)
	s.Require().Equal("Request address for transaction", receiverMessage.Text)
	s.Require().NotNil(receiverMessage.CommandParameters)
	s.Require().Equal(value, receiverMessage.CommandParameters.Value)
	s.Require().Equal(contract, receiverMessage.CommandParameters.Contract)
	s.Require().Equal(initialCommandID, receiverMessage.CommandParameters.ID)
	s.Require().Equal(common.CommandStateRequestAddressForTransaction, receiverMessage.CommandParameters.CommandState)

	// We decline the request
	response, err = theirMessenger.DeclineRequestAddressForTransaction(context.Background(), receiverMessage.ID)
	s.Require().NoError(err)
	s.Require().Len(response.Chats, 1)
	s.Require().Len(response.Messages, 1)

	senderMessage = response.Messages[0]
	s.Require().Equal(protobuf.ChatMessage_TRANSACTION_COMMAND, senderMessage.ContentType)
	s.Require().Equal("Request address for transaction declined", senderMessage.Text)
	s.Require().NotNil(senderMessage.CommandParameters)
	s.Require().Equal(value, senderMessage.CommandParameters.Value)
	s.Require().Equal(contract, senderMessage.CommandParameters.Contract)
	s.Require().Equal(common.CommandStateRequestAddressForTransactionDeclined, senderMessage.CommandParameters.CommandState)
	s.Require().Equal(initialCommandID, senderMessage.CommandParameters.ID)
	s.Require().Equal(receiverMessage.ID, senderMessage.Replace)

	// Wait for the message to reach its destination
	response, err = WaitOnMessengerResponse(
		s.m,
		func(r *MessengerResponse) bool { return len(r.Messages) > 0 },
		"no messages",
	)
	s.Require().NoError(err)

	s.Require().Len(response.Chats, 1)
	s.Require().Len(response.Messages, 1)

	receiverMessage = response.Messages[0]
	s.Require().Equal(protobuf.ChatMessage_TRANSACTION_COMMAND, receiverMessage.ContentType)
	s.Require().Equal("Request address for transaction declined", receiverMessage.Text)
	s.Require().NotNil(receiverMessage.CommandParameters)
	s.Require().Equal(value, receiverMessage.CommandParameters.Value)
	s.Require().Equal(contract, receiverMessage.CommandParameters.Contract)
	s.Require().Equal(common.CommandStateRequestAddressForTransactionDeclined, receiverMessage.CommandParameters.CommandState)
	s.Require().Equal(initialCommandID, receiverMessage.CommandParameters.ID)
	s.Require().Equal(initialCommandID, receiverMessage.Replace)
	s.Require().NoError(theirMessenger.Shutdown())
}

func (s *MessengerTransactionSuite) TestSendEthTransaction() {
	value := testValue
	contract := testContract

	theirMessenger := s.newMessenger(s.shh)
	s.Require().NoError(theirMessenger.Start())
	theirPkString := types.EncodeHex(crypto.FromECDSAPub(&theirMessenger.identity.PublicKey))

	receiverAddress := crypto.PubkeyToAddress(theirMessenger.identity.PublicKey)
	receiverAddressString := strings.ToLower(receiverAddress.Hex())

	chat := CreateOneToOneChat(theirPkString, &theirMessenger.identity.PublicKey, s.m.transport)
	err := s.m.SaveChat(&chat)
	s.Require().NoError(err)

	transactionHash := testTransactionHash
	signature, err := buildSignature(s.m.identity, &s.m.identity.PublicKey, transactionHash)
	s.Require().NoError(err)

	response, err := s.m.SendTransaction(context.Background(), theirPkString, value, contract, transactionHash, signature)
	s.Require().NoError(err)
	s.Require().NotNil(response)
	s.Require().Len(response.Chats, 1)
	s.Require().Len(response.Messages, 1)

	senderMessage := response.Messages[0]
	s.Require().Equal(protobuf.ChatMessage_TRANSACTION_COMMAND, senderMessage.ContentType)
	s.Require().Equal("Transaction sent", senderMessage.Text)
	s.Require().NotNil(senderMessage.CommandParameters)
	s.Require().Equal(transactionHash, senderMessage.CommandParameters.TransactionHash)
	s.Require().Equal(contract, senderMessage.CommandParameters.Contract)
	s.Require().Equal(value, senderMessage.CommandParameters.Value)
	s.Require().Equal(signature, senderMessage.CommandParameters.Signature)
	s.Require().Equal(common.CommandStateTransactionSent, senderMessage.CommandParameters.CommandState)
	s.Require().NotEmpty(senderMessage.ID)
	s.Require().Equal("", senderMessage.Replace)

	var transactions []*TransactionToValidate
	// Wait for the message to reach its destination
	err = tt.RetryWithBackOff(func() error {
		var err error

		_, err = theirMessenger.RetrieveAll()
		if err != nil {
			return err
		}
		transactions, err = theirMessenger.persistence.TransactionsToValidate()
		if err == nil && len(transactions) == 0 {
			err = errors.New("no transactions")
		}
		return err
	})
	s.Require().NoError(err)

	actualTransaction := transactions[0]

	s.Require().Equal(&s.m.identity.PublicKey, actualTransaction.From)
	s.Require().Equal(transactionHash, actualTransaction.TransactionHash)
	s.Require().True(actualTransaction.Validate)

	senderAddress := crypto.PubkeyToAddress(s.m.identity.PublicKey)

	client := MockEthClient{}
	valueBig, ok := big.NewInt(0).SetString(value, 10)
	s.Require().True(ok)
	client.messages = make(map[string]MockTransaction)
	client.messages[transactionHash] = MockTransaction{
		Status: coretypes.TransactionStatusSuccess,
		Message: coretypes.NewMessage(
			senderAddress,
			&receiverAddress,
			1,
			valueBig,
			0,
			nil,
			nil,
			false,
		),
	}
	theirMessenger.verifyTransactionClient = client
	response, err = theirMessenger.ValidateTransactions(context.Background(), []types.Address{receiverAddress})
	s.Require().NoError(err)

	s.Require().NotNil(response)
	s.Require().Len(response.Chats, 1)
	s.Require().Len(response.Messages, 1)

	receiverMessage := response.Messages[0]
	s.Require().Equal(protobuf.ChatMessage_TRANSACTION_COMMAND, receiverMessage.ContentType)

	s.Require().Equal("Transaction received", receiverMessage.Text)
	s.Require().NotNil(receiverMessage.CommandParameters)
	s.Require().Equal(value, receiverMessage.CommandParameters.Value)
	s.Require().Equal(strings.ToLower(receiverAddress.Hex()), receiverMessage.CommandParameters.Address)
	s.Require().Equal(transactionHash, receiverMessage.CommandParameters.TransactionHash)
	s.Require().Equal(receiverAddressString, receiverMessage.CommandParameters.Address)
	s.Require().Equal("", receiverMessage.CommandParameters.ID)
	s.Require().Equal(common.CommandStateTransactionSent, receiverMessage.CommandParameters.CommandState)
	s.Require().Equal(senderMessage.ID, receiverMessage.ID)
	s.Require().Equal("", receiverMessage.Replace)
	s.Require().NoError(theirMessenger.Shutdown())
}

func (s *MessengerTransactionSuite) TestSendTokenTransaction() {
	value := testValue
	contract := testContract

	theirMessenger := s.newMessenger(s.shh)
	s.Require().NoError(theirMessenger.Start())
	theirPkString := types.EncodeHex(crypto.FromECDSAPub(&theirMessenger.identity.PublicKey))

	receiverAddress := crypto.PubkeyToAddress(theirMessenger.identity.PublicKey)
	receiverAddressString := strings.ToLower(receiverAddress.Hex())

	chat := CreateOneToOneChat(theirPkString, &theirMessenger.identity.PublicKey, s.m.transport)
	err := s.m.SaveChat(&chat)
	s.Require().NoError(err)

	transactionHash := testTransactionHash
	signature, err := buildSignature(s.m.identity, &s.m.identity.PublicKey, transactionHash)
	s.Require().NoError(err)

	response, err := s.m.SendTransaction(context.Background(), theirPkString, value, contract, transactionHash, signature)
	s.Require().NoError(err)
	s.Require().NotNil(response)
	s.Require().Len(response.Chats, 1)
	s.Require().Len(response.Messages, 1)

	senderMessage := response.Messages[0]
	s.Require().Equal(protobuf.ChatMessage_TRANSACTION_COMMAND, senderMessage.ContentType)
	s.Require().Equal("Transaction sent", senderMessage.Text)
	s.Require().NotNil(senderMessage.CommandParameters)
	s.Require().Equal(transactionHash, senderMessage.CommandParameters.TransactionHash)
	s.Require().Equal(value, senderMessage.CommandParameters.Value)
	s.Require().Equal(contract, senderMessage.CommandParameters.Contract)
	s.Require().Equal(signature, senderMessage.CommandParameters.Signature)
	s.Require().Equal(common.CommandStateTransactionSent, senderMessage.CommandParameters.CommandState)
	s.Require().NotEmpty(senderMessage.ID)

	var transactions []*TransactionToValidate
	// Wait for the message to reach its destination
	err = tt.RetryWithBackOff(func() error {
		var err error

		_, err = theirMessenger.RetrieveAll()
		if err != nil {
			return err
		}
		transactions, err = theirMessenger.persistence.TransactionsToValidate()
		if err == nil && len(transactions) == 0 {
			err = errors.New("no transactions")
		}
		return err
	})
	s.Require().NoError(err)

	actualTransaction := transactions[0]

	s.Require().Equal(&s.m.identity.PublicKey, actualTransaction.From)
	s.Require().Equal(transactionHash, actualTransaction.TransactionHash)
	s.Require().True(actualTransaction.Validate)

	senderAddress := crypto.PubkeyToAddress(s.m.identity.PublicKey)

	contractAddress := types.HexToAddress(contract)
	client := MockEthClient{}
	valueBig, ok := big.NewInt(0).SetString(value, 10)
	s.Require().True(ok)
	client.messages = make(map[string]MockTransaction)
	client.messages[transactionHash] = MockTransaction{
		Status: coretypes.TransactionStatusSuccess,
		Message: coretypes.NewMessage(
			senderAddress,
			&contractAddress,
			1,
			nil,
			0,
			nil,
			buildData(transferFunction, receiverAddress, valueBig),
			false,
		),
	}
	theirMessenger.verifyTransactionClient = client
	response, err = theirMessenger.ValidateTransactions(context.Background(), []types.Address{receiverAddress})
	s.Require().NoError(err)

	s.Require().NotNil(response)
	s.Require().Len(response.Chats, 1)
	s.Require().Len(response.Messages, 1)

	receiverMessage := response.Messages[0]
	s.Require().Equal(protobuf.ChatMessage_TRANSACTION_COMMAND, receiverMessage.ContentType)

	s.Require().Equal("Transaction received", receiverMessage.Text)
	s.Require().NotNil(receiverMessage.CommandParameters)
	s.Require().Equal(value, receiverMessage.CommandParameters.Value)
	s.Require().Equal(contract, receiverMessage.CommandParameters.Contract)
	s.Require().Equal(transactionHash, receiverMessage.CommandParameters.TransactionHash)
	s.Require().Equal(receiverAddressString, receiverMessage.CommandParameters.Address)
	s.Require().Equal("", receiverMessage.CommandParameters.ID)
	s.Require().Equal(common.CommandStateTransactionSent, receiverMessage.CommandParameters.CommandState)
	s.Require().Equal(senderMessage.ID, receiverMessage.ID)
	s.Require().Equal(senderMessage.Replace, senderMessage.Replace)
	s.Require().NoError(theirMessenger.Shutdown())
}

func (s *MessengerTransactionSuite) TestAcceptRequestAddressForTransaction() {
	value := testValue
	contract := testContract
	theirMessenger := s.newMessenger(s.shh)
	s.Require().NoError(theirMessenger.Start())
	theirPkString := types.EncodeHex(crypto.FromECDSAPub(&theirMessenger.identity.PublicKey))

	myAddress := crypto.PubkeyToAddress(s.m.identity.PublicKey)

	chat := CreateOneToOneChat(theirPkString, &theirMessenger.identity.PublicKey, s.m.transport)
	err := s.m.SaveChat(&chat)
	s.Require().NoError(err)

	response, err := s.m.RequestAddressForTransaction(context.Background(), theirPkString, myAddress.Hex(), value, contract)
	s.Require().NoError(err)
	s.Require().NotNil(response)
	s.Require().Len(response.Chats, 1)
	s.Require().Len(response.Messages, 1)

	senderMessage := response.Messages[0]
	s.Require().Equal(protobuf.ChatMessage_TRANSACTION_COMMAND, senderMessage.ContentType)
	initialCommandID := senderMessage.ID

	s.Require().Equal("Request address for transaction", senderMessage.Text)
	s.Require().NotNil(senderMessage.CommandParameters)
	s.Require().Equal(value, senderMessage.CommandParameters.Value)
	s.Require().Equal(contract, senderMessage.CommandParameters.Contract)
	s.Require().Equal(initialCommandID, senderMessage.CommandParameters.ID)
	s.Require().Equal(common.CommandStateRequestAddressForTransaction, senderMessage.CommandParameters.CommandState)

	// Wait for the message to reach its destination
	response, err = WaitOnMessengerResponse(
		theirMessenger,
		func(r *MessengerResponse) bool { return len(r.Messages) > 0 },
		"no messages",
	)
	s.Require().NoError(err)

	s.Require().NotNil(response)
	s.Require().Len(response.Chats, 1)
	s.Require().Len(response.Messages, 1)

	receiverMessage := response.Messages[0]
	s.Require().Equal(protobuf.ChatMessage_TRANSACTION_COMMAND, receiverMessage.ContentType)
	s.Require().Equal("Request address for transaction", receiverMessage.Text)
	s.Require().NotNil(receiverMessage.CommandParameters)
	s.Require().Equal(value, receiverMessage.CommandParameters.Value)
	s.Require().Equal(contract, receiverMessage.CommandParameters.Contract)
	s.Require().Equal(initialCommandID, receiverMessage.CommandParameters.ID)
	s.Require().Equal(common.CommandStateRequestAddressForTransaction, receiverMessage.CommandParameters.CommandState)

	// We accept the request
	response, err = theirMessenger.AcceptRequestAddressForTransaction(context.Background(), receiverMessage.ID, "some-address")
	s.Require().NoError(err)
	s.Require().Len(response.Chats, 1)
	s.Require().Len(response.Messages, 1)

	senderMessage = response.Messages[0]
	s.Require().Equal(protobuf.ChatMessage_TRANSACTION_COMMAND, senderMessage.ContentType)
	s.Require().Equal("Request address for transaction accepted", senderMessage.Text)
	s.Require().NotNil(senderMessage.CommandParameters)
	s.Require().Equal(value, senderMessage.CommandParameters.Value)
	s.Require().Equal(contract, senderMessage.CommandParameters.Contract)
	s.Require().Equal(common.CommandStateRequestAddressForTransactionAccepted, senderMessage.CommandParameters.CommandState)
	s.Require().Equal(initialCommandID, senderMessage.CommandParameters.ID)
	s.Require().Equal("some-address", senderMessage.CommandParameters.Address)
	s.Require().Equal(receiverMessage.ID, senderMessage.Replace)

	// Wait for the message to reach its destination
	response, err = WaitOnMessengerResponse(
		s.m,
		func(r *MessengerResponse) bool { return len(r.Messages) > 0 },
		"no messages",
	)
	s.Require().NoError(err)

	s.Require().Len(response.Chats, 1)
	s.Require().Len(response.Messages, 1)

	receiverMessage = response.Messages[0]
	s.Require().Equal(protobuf.ChatMessage_TRANSACTION_COMMAND, receiverMessage.ContentType)
	s.Require().Equal("Request address for transaction accepted", receiverMessage.Text)
	s.Require().NotNil(receiverMessage.CommandParameters)
	s.Require().Equal(value, receiverMessage.CommandParameters.Value)
	s.Require().Equal(contract, receiverMessage.CommandParameters.Contract)
	s.Require().Equal(common.CommandStateRequestAddressForTransactionAccepted, receiverMessage.CommandParameters.CommandState)
	s.Require().Equal(initialCommandID, receiverMessage.CommandParameters.ID)
	s.Require().Equal("some-address", receiverMessage.CommandParameters.Address)
	s.Require().Equal(initialCommandID, receiverMessage.Replace)
	s.Require().NoError(theirMessenger.Shutdown())
}

func (s *MessengerTransactionSuite) TestDeclineRequestTransaction() {
	value := testValue
	contract := testContract
	receiverAddress := crypto.PubkeyToAddress(s.m.identity.PublicKey)
	receiverAddressString := strings.ToLower(receiverAddress.Hex())
	theirMessenger := s.newMessenger(s.shh)
	s.Require().NoError(theirMessenger.Start())
	theirPkString := types.EncodeHex(crypto.FromECDSAPub(&theirMessenger.identity.PublicKey))

	chat := CreateOneToOneChat(theirPkString, &theirMessenger.identity.PublicKey, s.m.transport)
	err := s.m.SaveChat(&chat)
	s.Require().NoError(err)

	response, err := s.m.RequestTransaction(context.Background(), theirPkString, value, contract, receiverAddressString)
	s.Require().NoError(err)
	s.Require().NotNil(response)
	s.Require().Len(response.Chats, 1)
	s.Require().Len(response.Messages, 1)

	senderMessage := response.Messages[0]
	s.Require().Equal(protobuf.ChatMessage_TRANSACTION_COMMAND, senderMessage.ContentType)
	initialCommandID := senderMessage.ID

	s.Require().Equal("Request transaction", senderMessage.Text)
	s.Require().NotNil(senderMessage.CommandParameters)
	s.Require().Equal(value, senderMessage.CommandParameters.Value)
	s.Require().Equal(contract, senderMessage.CommandParameters.Contract)
	s.Require().Equal(receiverAddressString, senderMessage.CommandParameters.Address)
	s.Require().Equal(initialCommandID, senderMessage.CommandParameters.ID)
	s.Require().Equal(common.CommandStateRequestTransaction, senderMessage.CommandParameters.CommandState)

	// Wait for the message to reach its destination
	response, err = WaitOnMessengerResponse(
		theirMessenger,
		func(r *MessengerResponse) bool { return len(r.Messages) > 0 },
		"no messages",
	)
	s.Require().NoError(err)

	s.Require().NotNil(response)
	s.Require().Len(response.Chats, 1)
	s.Require().Len(response.Messages, 1)

	receiverMessage := response.Messages[0]
	s.Require().Equal(protobuf.ChatMessage_TRANSACTION_COMMAND, receiverMessage.ContentType)
	s.Require().Equal("Request transaction", receiverMessage.Text)
	s.Require().NotNil(receiverMessage.CommandParameters)
	s.Require().Equal(value, receiverMessage.CommandParameters.Value)
	s.Require().Equal(contract, receiverMessage.CommandParameters.Contract)
	s.Require().Equal(receiverAddressString, receiverMessage.CommandParameters.Address)
	s.Require().Equal(initialCommandID, receiverMessage.CommandParameters.ID)
	s.Require().Equal(common.CommandStateRequestTransaction, receiverMessage.CommandParameters.CommandState)

	response, err = theirMessenger.DeclineRequestTransaction(context.Background(), initialCommandID)
	s.Require().NoError(err)
	s.Require().NotNil(response)
	s.Require().Len(response.Chats, 1)
	s.Require().Len(response.Messages, 1)

	senderMessage = response.Messages[0]
	s.Require().Equal(protobuf.ChatMessage_TRANSACTION_COMMAND, senderMessage.ContentType)

	s.Require().Equal("Transaction request declined", senderMessage.Text)
	s.Require().Equal(initialCommandID, senderMessage.CommandParameters.ID)
	s.Require().Equal(receiverMessage.ID, senderMessage.Replace)
	s.Require().Equal(common.CommandStateRequestTransactionDeclined, senderMessage.CommandParameters.CommandState)

	// Wait for the message to reach its destination
	response, err = WaitOnMessengerResponse(
		s.m,
		func(r *MessengerResponse) bool { return len(r.Messages) > 0 },
		"no messages",
	)
	s.Require().NoError(err)

	s.Require().NotNil(response)
	s.Require().Len(response.Chats, 1)
	s.Require().Len(response.Messages, 1)

	receiverMessage = response.Messages[0]
	s.Require().Equal(protobuf.ChatMessage_TRANSACTION_COMMAND, receiverMessage.ContentType)

	s.Require().Equal("Transaction request declined", receiverMessage.Text)
	s.Require().Equal(initialCommandID, receiverMessage.CommandParameters.ID)
	s.Require().Equal(initialCommandID, receiverMessage.Replace)
	s.Require().Equal(common.CommandStateRequestTransactionDeclined, receiverMessage.CommandParameters.CommandState)
	s.Require().NoError(theirMessenger.Shutdown())
}

func (s *MessengerTransactionSuite) TestRequestTransaction() {
	value := testValue
	contract := testContract
	receiverAddress := crypto.PubkeyToAddress(s.m.identity.PublicKey)
	receiverAddressString := strings.ToLower(receiverAddress.Hex())
	theirMessenger := s.newMessenger(s.shh)
	s.Require().NoError(theirMessenger.Start())
	theirPkString := types.EncodeHex(crypto.FromECDSAPub(&theirMessenger.identity.PublicKey))

	chat := CreateOneToOneChat(theirPkString, &theirMessenger.identity.PublicKey, s.m.transport)
	err := s.m.SaveChat(&chat)
	s.Require().NoError(err)

	response, err := s.m.RequestTransaction(context.Background(), theirPkString, value, contract, receiverAddressString)
	s.Require().NoError(err)
	s.Require().NotNil(response)
	s.Require().Len(response.Chats, 1)
	s.Require().Len(response.Messages, 1)

	senderMessage := response.Messages[0]
	s.Require().Equal(protobuf.ChatMessage_TRANSACTION_COMMAND, senderMessage.ContentType)
	initialCommandID := senderMessage.ID

	s.Require().Equal("Request transaction", senderMessage.Text)
	s.Require().NotNil(senderMessage.CommandParameters)
	s.Require().Equal(value, senderMessage.CommandParameters.Value)
	s.Require().Equal(contract, senderMessage.CommandParameters.Contract)
	s.Require().Equal(receiverAddressString, senderMessage.CommandParameters.Address)
	s.Require().Equal(initialCommandID, senderMessage.CommandParameters.ID)
	s.Require().Equal(common.CommandStateRequestTransaction, senderMessage.CommandParameters.CommandState)

	// Wait for the message to reach its destination
	response, err = WaitOnMessengerResponse(
		theirMessenger,
		func(r *MessengerResponse) bool { return len(r.Messages) > 0 },
		"no messages",
	)
	s.Require().NoError(err)

	s.Require().NotNil(response)
	s.Require().Len(response.Chats, 1)
	s.Require().Len(response.Messages, 1)

	receiverMessage := response.Messages[0]
	s.Require().Equal(protobuf.ChatMessage_TRANSACTION_COMMAND, receiverMessage.ContentType)
	s.Require().Equal("Request transaction", receiverMessage.Text)
	s.Require().NotNil(receiverMessage.CommandParameters)
	s.Require().Equal(value, receiverMessage.CommandParameters.Value)
	s.Require().Equal(contract, receiverMessage.CommandParameters.Contract)
	s.Require().Equal(receiverAddressString, receiverMessage.CommandParameters.Address)
	s.Require().Equal(initialCommandID, receiverMessage.CommandParameters.ID)
	s.Require().Equal(common.CommandStateRequestTransaction, receiverMessage.CommandParameters.CommandState)

	transactionHash := "0x412a851ac2ae51cad34a56c8a9cfee55d577ac5e1ac71cf488a2f2093a373799"
	signature, err := buildSignature(theirMessenger.identity, &theirMessenger.identity.PublicKey, transactionHash)
	s.Require().NoError(err)
	response, err = theirMessenger.AcceptRequestTransaction(context.Background(), transactionHash, initialCommandID, signature)
	s.Require().NoError(err)
	s.Require().NotNil(response)
	s.Require().Len(response.Chats, 1)
	s.Require().Len(response.Messages, 1)

	senderMessage = response.Messages[0]
	s.Require().Equal(protobuf.ChatMessage_TRANSACTION_COMMAND, senderMessage.ContentType)

	s.Require().Equal("Transaction sent", senderMessage.Text)
	s.Require().NotNil(senderMessage.CommandParameters)
	s.Require().Equal(value, senderMessage.CommandParameters.Value)
	s.Require().Equal(contract, senderMessage.CommandParameters.Contract)
	s.Require().Equal(transactionHash, senderMessage.CommandParameters.TransactionHash)
	s.Require().Equal(receiverAddressString, senderMessage.CommandParameters.Address)
	s.Require().Equal(initialCommandID, senderMessage.CommandParameters.ID)
	s.Require().Equal(signature, senderMessage.CommandParameters.Signature)
	s.Require().NotEmpty(senderMessage.ID)
	s.Require().Equal(receiverMessage.ID, senderMessage.Replace)
	s.Require().Equal(common.CommandStateTransactionSent, senderMessage.CommandParameters.CommandState)

	var transactions []*TransactionToValidate
	// Wait for the message to reach its destination
	err = tt.RetryWithBackOff(func() error {
		var err error

		_, err = s.m.RetrieveAll()
		if err != nil {
			return err
		}
		transactions, err = s.m.persistence.TransactionsToValidate()
		if err == nil && len(transactions) == 0 {
			err = errors.New("no transactions")
		}
		return err
	})
	s.Require().NoError(err)

	actualTransaction := transactions[0]

	s.Require().Equal(&theirMessenger.identity.PublicKey, actualTransaction.From)
	s.Require().Equal(transactionHash, actualTransaction.TransactionHash)
	s.Require().True(actualTransaction.Validate)
	s.Require().Equal(initialCommandID, actualTransaction.CommandID)

	senderAddress := crypto.PubkeyToAddress(theirMessenger.identity.PublicKey)

	contractAddress := types.HexToAddress(contract)
	client := MockEthClient{}
	valueBig, ok := big.NewInt(0).SetString(value, 10)
	s.Require().True(ok)
	client.messages = make(map[string]MockTransaction)
	client.messages[transactionHash] = MockTransaction{
		Status: coretypes.TransactionStatusSuccess,
		Message: coretypes.NewMessage(
			senderAddress,
			&contractAddress,
			1,
			nil,
			0,
			nil,
			buildData(transferFunction, receiverAddress, valueBig),
			false,
		),
	}
	s.m.verifyTransactionClient = client
	response, err = s.m.ValidateTransactions(context.Background(), []types.Address{receiverAddress})
	s.Require().NoError(err)

	s.Require().NotNil(response)
	s.Require().Len(response.Chats, 1)
	s.Require().Len(response.Messages, 1)

	receiverMessage = response.Messages[0]
	s.Require().Equal(protobuf.ChatMessage_TRANSACTION_COMMAND, receiverMessage.ContentType)

	s.Require().Equal("Transaction received", receiverMessage.Text)
	s.Require().NotNil(receiverMessage.CommandParameters)
	s.Require().Equal(value, receiverMessage.CommandParameters.Value)
	s.Require().Equal(contract, receiverMessage.CommandParameters.Contract)
	s.Require().Equal(transactionHash, receiverMessage.CommandParameters.TransactionHash)
	s.Require().Equal(receiverAddressString, receiverMessage.CommandParameters.Address)
	s.Require().Equal(initialCommandID, receiverMessage.CommandParameters.ID)
	s.Require().Equal(signature, receiverMessage.CommandParameters.Signature)
	s.Require().Equal(common.CommandStateTransactionSent, receiverMessage.CommandParameters.CommandState)
	s.Require().Equal(senderMessage.ID, receiverMessage.ID)
	s.Require().Equal(senderMessage.Replace, senderMessage.Replace)
	s.Require().NoError(theirMessenger.Shutdown())
}

type MockTransaction struct {
	Status  coretypes.TransactionStatus
	Message coretypes.Message
}

type MockEthClient struct {
	messages map[string]MockTransaction
}

type mockSendMessagesRequest struct {
	types.Waku
	req types.MessagesRequest
}

func (m MockEthClient) TransactionByHash(ctx context.Context, hash types.Hash) (coretypes.Message, coretypes.TransactionStatus, error) {
	mockTransaction, ok := m.messages[hash.Hex()]
	if !ok {
		return coretypes.Message{}, coretypes.TransactionStatusFailed, nil
	}
	return mockTransaction.Message, mockTransaction.Status, nil
}
