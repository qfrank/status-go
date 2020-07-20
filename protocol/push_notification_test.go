package protocol

import (
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"errors"
	"io/ioutil"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/suite"
	"go.uber.org/zap"

	gethbridge "github.com/status-im/status-go/eth-node/bridge/geth"
	"github.com/status-im/status-go/eth-node/crypto"
	"github.com/status-im/status-go/eth-node/types"
	"github.com/status-im/status-go/protocol/common"
	"github.com/status-im/status-go/protocol/push_notification_client"
	"github.com/status-im/status-go/protocol/push_notification_server"
	"github.com/status-im/status-go/protocol/tt"
	"github.com/status-im/status-go/whisper/v6"
)

func TestMessengerPushNotificationSuite(t *testing.T) {
	suite.Run(t, new(MessengerPushNotificationSuite))
}

type MessengerPushNotificationSuite struct {
	suite.Suite
	m          *Messenger        // main instance of Messenger
	privateKey *ecdsa.PrivateKey // private key for the main instance of Messenger
	// If one wants to send messages between different instances of Messenger,
	// a single Whisper service should be shared.
	shh      types.Whisper
	tmpFiles []*os.File // files to clean up
	logger   *zap.Logger
}

func (s *MessengerPushNotificationSuite) SetupTest() {
	s.logger = tt.MustCreateTestLogger()

	config := whisper.DefaultConfig
	config.MinimumAcceptedPOW = 0
	shh := whisper.New(&config)
	s.shh = gethbridge.NewGethWhisperWrapper(shh)
	s.Require().NoError(shh.Start(nil))

	s.m = s.newMessenger(s.shh)
	s.privateKey = s.m.identity
}

func (s *MessengerPushNotificationSuite) newMessengerWithOptions(shh types.Whisper, privateKey *ecdsa.PrivateKey, options []Option) *Messenger {
	tmpFile, err := ioutil.TempFile("", "")
	s.Require().NoError(err)

	m, err := NewMessenger(
		privateKey,
		&testNode{shh: shh},
		uuid.New().String(),
		options...,
	)
	s.Require().NoError(err)

	err = m.Init()
	s.Require().NoError(err)

	s.tmpFiles = append(s.tmpFiles, tmpFile)

	return m
}

func (s *MessengerPushNotificationSuite) newMessengerWithKey(shh types.Whisper, privateKey *ecdsa.PrivateKey) *Messenger {
	tmpFile, err := ioutil.TempFile("", "")
	s.Require().NoError(err)

	options := []Option{
		WithCustomLogger(s.logger),
		WithMessagesPersistenceEnabled(),
		WithDatabaseConfig(tmpFile.Name(), "some-key"),
		WithDatasync(),
	}
	return s.newMessengerWithOptions(shh, privateKey, options)
}

func (s *MessengerPushNotificationSuite) newMessenger(shh types.Whisper) *Messenger {
	privateKey, err := crypto.GenerateKey()
	s.Require().NoError(err)

	return s.newMessengerWithKey(s.shh, privateKey)
}

func (s *MessengerPushNotificationSuite) newPushNotificationServer(shh types.Whisper) *Messenger {
	privateKey, err := crypto.GenerateKey()
	s.Require().NoError(err)

	tmpFile, err := ioutil.TempFile("", "")
	s.Require().NoError(err)

	serverConfig := &push_notification_server.Config{
		Logger:   s.logger,
		Identity: privateKey,
	}

	options := []Option{
		WithCustomLogger(s.logger),
		WithMessagesPersistenceEnabled(),
		WithDatabaseConfig(tmpFile.Name(), "some-key"),
		WithPushNotificationServerConfig(serverConfig),
		WithDatasync(),
	}
	return s.newMessengerWithOptions(shh, privateKey, options)
}

func (s *MessengerPushNotificationSuite) TestReceivePushNotification() {

	bob1DeviceToken := "token-1"
	bob2DeviceToken := "token-2"

	bob1 := s.m
	bob2 := s.newMessengerWithKey(s.shh, s.m.identity)
	server := s.newPushNotificationServer(s.shh)
	alice := s.newMessenger(s.shh)
	// start alice and enable sending push notifications
	s.Require().NoError(alice.Start())
	s.Require().NoError(alice.EnableSendingPushNotifications())
	bobInstallationIDs := []string{bob1.installationID, bob2.installationID}

	// Register bob1
	err := bob1.AddPushNotificationServer(context.Background(), &server.identity.PublicKey)
	s.Require().NoError(err)

	err = bob1.RegisterForPushNotifications(context.Background(), bob1DeviceToken)

	// Pull servers  and check we registered
	err = tt.RetryWithBackOff(func() error {
		_, err = server.RetrieveAll()
		if err != nil {
			return err
		}
		_, err = bob1.RetrieveAll()
		if err != nil {
			return err
		}
		registered, err := bob1.RegisteredForPushNotifications()
		if err != nil {
			return err
		}
		if !registered {
			return errors.New("not registered")
		}
		return nil
	})
	// Make sure we receive it
	s.Require().NoError(err)
	bob1Servers, err := bob1.GetPushNotificationServers()
	s.Require().NoError(err)

	// Register bob2
	err = bob2.AddPushNotificationServer(context.Background(), &server.identity.PublicKey)
	s.Require().NoError(err)

	err = bob2.RegisterForPushNotifications(context.Background(), bob2DeviceToken)
	s.Require().NoError(err)

	err = tt.RetryWithBackOff(func() error {
		_, err = server.RetrieveAll()
		if err != nil {
			return err
		}
		_, err = bob2.RetrieveAll()
		if err != nil {
			return err
		}

		registered, err := bob2.RegisteredForPushNotifications()
		if err != nil {
			return err
		}
		if !registered {
			return errors.New("not registered")
		}
		return nil
	})
	// Make sure we receive it
	s.Require().NoError(err)
	bob2Servers, err := bob2.GetPushNotificationServers()
	s.Require().NoError(err)

	// Create one to one chat & send message
	pkString := hex.EncodeToString(crypto.FromECDSAPub(&s.m.identity.PublicKey))
	chat := CreateOneToOneChat(pkString, &s.m.identity.PublicKey, alice.transport)
	s.Require().NoError(alice.SaveChat(&chat))
	inputMessage := buildTestMessage(chat)
	response, err := alice.SendChatMessage(context.Background(), inputMessage)
	s.Require().NoError(err)
	messageIDString := response.Messages[0].ID
	messageID, err := hex.DecodeString(messageIDString[2:])
	s.Require().NoError(err)

	var info []*push_notification_client.PushNotificationInfo
	err = tt.RetryWithBackOff(func() error {
		_, err = server.RetrieveAll()
		if err != nil {
			return err
		}
		_, err = alice.RetrieveAll()
		if err != nil {
			return err
		}

		info, err = alice.pushNotificationClient.GetPushNotificationInfo(&bob1.identity.PublicKey, bobInstallationIDs)
		if err != nil {
			return err
		}
		// Check we have replies for both bob1 and bob2
		if len(info) != 2 {
			return errors.New("info not fetched")
		}
		return nil

	})

	s.Require().NoError(err)

	// Check we have replies for both bob1 and bob2
	var bob1Info, bob2Info *push_notification_client.PushNotificationInfo

	if info[0].AccessToken == bob1Servers[0].AccessToken {
		bob1Info = info[0]
		bob2Info = info[1]
	} else {
		bob2Info = info[0]
		bob1Info = info[1]
	}

	s.Require().NotNil(bob1Info)
	s.Require().Equal(bob1.installationID, bob1Info.InstallationID)
	s.Require().Equal(bob1Servers[0].AccessToken, bob1Info.AccessToken)
	s.Require().Equal(&bob1.identity.PublicKey, bob1Info.PublicKey)

	s.Require().NotNil(bob2Info)
	s.Require().Equal(bob2.installationID, bob2Info.InstallationID)
	s.Require().Equal(bob2Servers[0].AccessToken, bob2Info.AccessToken)
	s.Require().Equal(&bob2.identity.PublicKey, bob2Info.PublicKey)

	retrievedNotificationInfo, err := alice.pushNotificationClient.GetPushNotificationInfo(&bob1.identity.PublicKey, bobInstallationIDs)

	s.Require().NoError(err)
	s.Require().NotNil(retrievedNotificationInfo)
	s.Require().Len(retrievedNotificationInfo, 2)

	var sentNotification *push_notification_client.SentNotification
	err = tt.RetryWithBackOff(func() error {
		_, err = server.RetrieveAll()
		if err != nil {
			return err
		}
		_, err = alice.RetrieveAll()
		if err != nil {
			return err
		}
		sentNotification, err = alice.pushNotificationClient.GetSentNotification(common.HashPublicKey(&bob1.identity.PublicKey), bob1.installationID, messageID)
		if err != nil {
			return err
		}
		if sentNotification == nil {
			return errors.New("sent notification not found")
		}
		if !sentNotification.Success {
			return errors.New("sent notification not successul")
		}
		return nil
	})
	s.Require().NoError(err)
}

func (s *MessengerPushNotificationSuite) TestReceivePushNotificationFromContactOnly() {

	bobDeviceToken := "token-1"

	bob := s.m
	server := s.newPushNotificationServer(s.shh)
	alice := s.newMessenger(s.shh)
	// start alice and enable push notifications
	s.Require().NoError(alice.Start())
	s.Require().NoError(alice.EnableSendingPushNotifications())
	bobInstallationIDs := []string{bob.installationID}

	// Register bob
	err := bob.AddPushNotificationServer(context.Background(), &server.identity.PublicKey)
	s.Require().NoError(err)

	// Add alice has a contact
	aliceContact := &Contact{
		ID:         types.EncodeHex(crypto.FromECDSAPub(&alice.identity.PublicKey)),
		Name:       "Some Contact",
		SystemTags: []string{contactAdded},
	}

	err = bob.SaveContact(aliceContact)
	s.Require().NoError(err)

	// Enable from contacts only
	err = bob.EnablePushNotificationsFromContactsOnly()
	s.Require().NoError(err)

	err = bob.RegisterForPushNotifications(context.Background(), bobDeviceToken)
	s.Require().NoError(err)

	// Pull servers  and check we registered
	err = tt.RetryWithBackOff(func() error {
		_, err = server.RetrieveAll()
		if err != nil {
			return err
		}
		_, err = bob.RetrieveAll()
		if err != nil {
			return err
		}
		registered, err := bob.RegisteredForPushNotifications()
		if err != nil {
			return err
		}
		if !registered {
			return errors.New("not registered")
		}
		return nil
	})
	// Make sure we receive it
	s.Require().NoError(err)
	bobServers, err := bob.GetPushNotificationServers()
	s.Require().NoError(err)

	// Create one to one chat & send message
	pkString := hex.EncodeToString(crypto.FromECDSAPub(&s.m.identity.PublicKey))
	chat := CreateOneToOneChat(pkString, &s.m.identity.PublicKey, alice.transport)
	s.Require().NoError(alice.SaveChat(&chat))
	inputMessage := buildTestMessage(chat)
	response, err := alice.SendChatMessage(context.Background(), inputMessage)
	s.Require().NoError(err)
	messageIDString := response.Messages[0].ID
	messageID, err := hex.DecodeString(messageIDString[2:])
	s.Require().NoError(err)

	var info []*push_notification_client.PushNotificationInfo
	err = tt.RetryWithBackOff(func() error {
		_, err = server.RetrieveAll()
		if err != nil {
			return err
		}
		_, err = alice.RetrieveAll()
		if err != nil {
			return err
		}

		info, err = alice.pushNotificationClient.GetPushNotificationInfo(&bob.identity.PublicKey, bobInstallationIDs)
		if err != nil {
			return err
		}
		// Check we have replies for bob
		if len(info) != 1 {
			return errors.New("info not fetched")
		}
		return nil

	})
	s.Require().NoError(err)

	s.Require().NotNil(info)
	s.Require().Equal(bob.installationID, info[0].InstallationID)
	s.Require().Equal(bobServers[0].AccessToken, info[0].AccessToken)
	s.Require().Equal(&bob.identity.PublicKey, info[0].PublicKey)

	retrievedNotificationInfo, err := alice.pushNotificationClient.GetPushNotificationInfo(&bob.identity.PublicKey, bobInstallationIDs)
	s.Require().NoError(err)
	s.Require().NotNil(retrievedNotificationInfo)
	s.Require().Len(retrievedNotificationInfo, 1)

	var sentNotification *push_notification_client.SentNotification
	err = tt.RetryWithBackOff(func() error {
		_, err = server.RetrieveAll()
		if err != nil {
			return err
		}
		_, err = alice.RetrieveAll()
		if err != nil {
			return err
		}
		sentNotification, err = alice.pushNotificationClient.GetSentNotification(common.HashPublicKey(&bob.identity.PublicKey), bob.installationID, messageID)
		if err != nil {
			return err
		}
		if sentNotification == nil {
			return errors.New("sent notification not found")
		}
		if !sentNotification.Success {
			return errors.New("sent notification not successul")
		}
		return nil
	})

	s.Require().NoError(err)
}

func (s *MessengerPushNotificationSuite) TestReceivePushNotificationRetries() {

	bobDeviceToken := "token-1"

	bob := s.m
	server := s.newPushNotificationServer(s.shh)
	alice := s.newMessenger(s.shh)
	// another contact to invalidate the token
	frank := s.newMessenger(s.shh)
	// start alice and enable push notifications
	s.Require().NoError(alice.Start())
	s.Require().NoError(alice.EnableSendingPushNotifications())
	bobInstallationIDs := []string{bob.installationID}

	// Register bob
	err := bob.AddPushNotificationServer(context.Background(), &server.identity.PublicKey)
	s.Require().NoError(err)

	// Add alice has a contact
	aliceContact := &Contact{
		ID:         types.EncodeHex(crypto.FromECDSAPub(&alice.identity.PublicKey)),
		Name:       "Some Contact",
		SystemTags: []string{contactAdded},
	}

	err = bob.SaveContact(aliceContact)
	s.Require().NoError(err)

	// Add frank has a contact
	frankContact := &Contact{
		ID:         types.EncodeHex(crypto.FromECDSAPub(&frank.identity.PublicKey)),
		Name:       "Some Contact",
		SystemTags: []string{contactAdded},
	}

	err = bob.SaveContact(frankContact)
	s.Require().NoError(err)

	// Enable from contacts only
	err = bob.EnablePushNotificationsFromContactsOnly()
	s.Require().NoError(err)

	err = bob.RegisterForPushNotifications(context.Background(), bobDeviceToken)
	s.Require().NoError(err)

	// Pull servers  and check we registered
	err = tt.RetryWithBackOff(func() error {
		_, err = server.RetrieveAll()
		if err != nil {
			return err
		}
		_, err = bob.RetrieveAll()
		if err != nil {
			return err
		}
		registered, err := bob.RegisteredForPushNotifications()
		if err != nil {
			return err
		}
		if !registered {
			return errors.New("not registered")
		}
		return nil
	})
	// Make sure we receive it
	s.Require().NoError(err)
	bobServers, err := bob.GetPushNotificationServers()
	s.Require().NoError(err)

	// Create one to one chat & send message
	pkString := hex.EncodeToString(crypto.FromECDSAPub(&s.m.identity.PublicKey))
	chat := CreateOneToOneChat(pkString, &s.m.identity.PublicKey, alice.transport)
	s.Require().NoError(alice.SaveChat(&chat))
	inputMessage := buildTestMessage(chat)
	_, err = alice.SendChatMessage(context.Background(), inputMessage)
	s.Require().NoError(err)

	// We check that alice retrieves the info from the server
	var info []*push_notification_client.PushNotificationInfo
	err = tt.RetryWithBackOff(func() error {
		_, err = server.RetrieveAll()
		if err != nil {
			return err
		}
		_, err = alice.RetrieveAll()
		if err != nil {
			return err
		}

		info, err = alice.pushNotificationClient.GetPushNotificationInfo(&bob.identity.PublicKey, bobInstallationIDs)
		if err != nil {
			return err
		}
		// Check we have replies for bob
		if len(info) != 1 {
			return errors.New("info not fetched")
		}
		return nil

	})
	s.Require().NoError(err)

	s.Require().NotNil(info)
	s.Require().Equal(bob.installationID, info[0].InstallationID)
	s.Require().Equal(bobServers[0].AccessToken, info[0].AccessToken)
	s.Require().Equal(&bob.identity.PublicKey, info[0].PublicKey)

	// The message has been sent, but not received, now we remove a contact so that the token is invalidated
	frankContact = &Contact{
		ID:         types.EncodeHex(crypto.FromECDSAPub(&frank.identity.PublicKey)),
		Name:       "Some Contact",
		SystemTags: []string{},
	}
	err = bob.SaveContact(frankContact)
	s.Require().NoError(err)

	// Re-registration should be triggered, pull from server and bob to check we are correctly registered
	// Pull servers  and check we registered
	err = tt.RetryWithBackOff(func() error {
		_, err = server.RetrieveAll()
		if err != nil {
			return err
		}
		_, err = bob.RetrieveAll()
		if err != nil {
			return err
		}
		registered, err := bob.RegisteredForPushNotifications()
		if err != nil {
			return err
		}
		if !registered {
			return errors.New("not registered")
		}
		return nil
	})

	newBobServers, err := bob.GetPushNotificationServers()
	s.Require().NoError(err)
	// Make sure access token is not the same
	s.Require().NotEqual(newBobServers[0].AccessToken, bobServers[0].AccessToken)

	// Send another message, here the token will not be valid
	inputMessage = buildTestMessage(chat)
	response, err := alice.SendChatMessage(context.Background(), inputMessage)
	s.Require().NoError(err)
	messageIDString := response.Messages[0].ID
	messageID, err := hex.DecodeString(messageIDString[2:])
	s.Require().NoError(err)

	err = tt.RetryWithBackOff(func() error {
		_, err = server.RetrieveAll()
		if err != nil {
			return err
		}
		_, err = alice.RetrieveAll()
		if err != nil {
			return err
		}

		info, err = alice.pushNotificationClient.GetPushNotificationInfo(&bob.identity.PublicKey, bobInstallationIDs)
		if err != nil {
			return err
		}
		// Check we have replies for bob
		if len(info) != 1 {
			return errors.New("info not fetched")
		}
		if newBobServers[0].AccessToken != info[0].AccessToken {
			return errors.New("still using the old access token")
		}
		return nil

	})
	s.Require().NoError(err)

	s.Require().NotNil(info)
	s.Require().Equal(bob.installationID, info[0].InstallationID)
	s.Require().Equal(newBobServers[0].AccessToken, info[0].AccessToken)
	s.Require().Equal(&bob.identity.PublicKey, info[0].PublicKey)

	retrievedNotificationInfo, err := alice.pushNotificationClient.GetPushNotificationInfo(&bob.identity.PublicKey, bobInstallationIDs)
	s.Require().NoError(err)
	s.Require().NotNil(retrievedNotificationInfo)
	s.Require().Len(retrievedNotificationInfo, 1)

	var sentNotification *push_notification_client.SentNotification
	err = tt.RetryWithBackOff(func() error {
		_, err = server.RetrieveAll()
		if err != nil {
			return err
		}
		_, err = alice.RetrieveAll()
		if err != nil {
			return err
		}
		sentNotification, err = alice.pushNotificationClient.GetSentNotification(common.HashPublicKey(&bob.identity.PublicKey), bob.installationID, messageID)
		if err != nil {
			return err
		}
		if sentNotification == nil {
			return errors.New("sent notification not found")
		}
		if !sentNotification.Success {
			return errors.New("sent notification not successul")
		}
		return nil
	})

	s.Require().NoError(err)
}
