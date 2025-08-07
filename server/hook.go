package main

import (
	"fmt"
	"github.com/mattermost/mattermost/server/public/model"
	"github.com/mattermost/mattermost/server/public/plugin"
)

func (p *Plugin) MessageWillBePosted(_ *plugin.Context, post *model.Post) (*model.Post, string) {
	if post.UserId != p.BotUserID {
		return nil, ""
	}
	encrMethod := p.ChanEncrMethods.get(post.ChannelId)
	if encrMethod == ChanEncryptionMethodNone {
		return nil, ""
	}

	if p.getConfiguration().BotCanAlwaysPost {
		user, appErr := p.API.GetUser(post.UserId)
		if appErr != nil {
			return nil, fmt.Sprintf("unable to check if user is a bot: %s", appErr.Error())
		}
		if user.IsBot {
			return nil, ""
		}
	}

	if _, has := p.AlwaysAllowMsgTypes[post.Type]; has {
		return nil, ""
	}
	if post.Type != "custom_e2ee" {
		return nil, "Unencrypted message can not be sent on encrypted channel"
	}
	return nil, ""
}
