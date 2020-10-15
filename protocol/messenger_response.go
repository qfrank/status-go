package protocol

import (
	"github.com/status-im/status-go/protocol/common"
	"github.com/status-im/status-go/protocol/encryption/multidevice"
)

type MessengerResponse struct {
	Chats               []*Chat                              `json:"chats,omitempty"`
	Messages            []*common.Message                    `json:"messages,omitempty"`
	Contacts            []*Contact                           `json:"contacts,omitempty"`
	Installations       []*multidevice.Installation          `json:"installations,omitempty"`
	EmojiReactions      []*EmojiReaction                     `json:"emojiReactions,omitempty"`
	Invitations         []*GroupChatInvitation               `json:"invitations,omitempty"`
	Organisations       []*organisations.Organisation        `json:"organisations,omitempty"`
	OrganisationChanges []*organisations.OrganisationChanges `json:"organisationsChanges,omitempty"`
	Filters             []*transport.Filter                  `json:"filters,omitempty"`
	RemovedFilters      []string                             `json:"removedFilters,omitempty"`
}

func (m *MessengerResponse) IsEmpty() bool {

	return len(m.Chats)+len(m.Messages)+len(m.Contacts)+len(m.Installations)+len(m.Invitations)+len(m.EmojiReactions)+len(m.Organisations)+len(m.OrganisationChanges)+len(m.Filters)+len(m.RemovedFilters)+len(m.RemovedChats) == 0
}

// Merge takes another response and appends the new Chats & new Messages and replaces
// the existing Messages & Chats if they have the same ID
func (m *MessengerResponse) Merge(response *MessengerResponse) error {
	if len(response.Contacts)+len(response.Installations)+len(response.EmojiReactions)+len(response.Invitations) != 0 {
		return ErrNotImplemented
	}

	m.overrideChats(response.Chats)
	m.overrideMessages(response.Messages)

	return nil
}

// overrideChats append new chats and override existing ones in response.Chats
func (m *MessengerResponse) overrideChats(chats []*Chat) {
	for _, overrideChat := range chats {
		var found = false
		for idx, chat := range m.Chats {
			if chat.ID == overrideChat.ID {
				m.Chats[idx] = overrideChat
				found = true
			}
		}
		if !found {
			m.Chats = append(m.Chats, overrideChat)
		}
	}
}

// overrideMessages append new messages and override existing ones in response.Messages
func (m *MessengerResponse) overrideMessages(messages []*common.Message) {
	for _, overrideMessage := range messages {
		var found = false
		for idx, chat := range m.Messages {
			if chat.ID == overrideMessage.ID {
				m.Messages[idx] = overrideMessage
				found = true
			}
		}
		if !found {
			m.Messages = append(m.Messages, overrideMessage)
		}
	}
}