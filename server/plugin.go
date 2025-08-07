package main

import (
	"fmt"
	"github.com/gorilla/mux"
	"github.com/mattermost/mattermost/server/public/model"
	"github.com/mattermost/mattermost/server/public/plugin"
	"github.com/pkg/errors"
	"strings"
	"sync"
)

const (
	helpTextHeader = "###### Mattermost E2EE Plugin - Slash command help\n"
	helpText       = `
* |/e2ee help| - print this help message.
* |/e2ee init [--force] [gpg key fingerprint]| - initialize E2EE for your account. This will generate a new key for your session. Use --force to erase an existing key.
* |/e2ee start| - encrypt the messages you send in this channel.
* |/e2ee stop| - do not encrypt the messages you send in this channel.
* |/e2ee import| - import your private key into this device.
* |/e2ee show_backup| - show saved encrypted GPG backup.
`
	autoCompleteDescription = "Available commands: init import help"
	autoCompleteHint        = "[command][subcommands]"
	pluginDescription       = "End to end message encryption"
	slashCommandName        = "e2ee"
)

// Plugin implements the interface expected by the Mattermost server to communicate between the server and plugin processes.
type Plugin struct {
	plugin.MattermostPlugin

	BotUserID string

	ChanEncrMethods *ChanEncrMethodDB

	configurationLock sync.RWMutex

	configuration *configuration

	AlwaysAllowMsgTypes map[string]bool

	router *mux.Router
}

func GetSlashCommand() *model.Command {
	return &model.Command{
		Trigger:          slashCommandName,
		DisplayName:      slashCommandName,
		Description:      pluginDescription,
		AutoComplete:     false,
		AutoCompleteDesc: autoCompleteDescription,
		AutoCompleteHint: autoCompleteHint,
	}
}

func (p *Plugin) OnActivate() error {
	p.InitializeAPI()

	err := p.API.RegisterCommand(GetSlashCommand())
	if err != nil {
		return errors.Wrap(err, "failed to register Slash command")
	}

	botID, err := p.API.EnsureBotUser(&model.Bot{
		Username:    "e2ee",
		DisplayName: "E2EE",
		Description: "Created by the E2EE plugin",
	})
	if err != nil {
		return errors.Wrap(err, "failed to ensure bot")
	}
	p.BotUserID = botID
	return nil
}

func (p *Plugin) PostCommandResponse(args *model.CommandArgs, text string) {
	post := &model.Post{
		UserId:    p.BotUserID,
		ChannelId: args.ChannelId,
		Message:   text,
	}
	_ = p.API.SendEphemeralPost(args.UserId, post)
}

func (p *Plugin) ShowGPGBackup(args *model.CommandArgs) *model.AppError {
	backupGPG, appErr := p.API.KVGet(StoreBackupGPGKey(args.UserId))
	if appErr != nil {
		return appErr
	}
	if backupGPG == nil {
		return &model.AppError{Message: "Failed to find BackupGPG"}
	}
	p.PostCommandResponse(args, string(backupGPG))
	return nil
}

func (p *Plugin) ExecuteCommand(_ *plugin.Context, args *model.CommandArgs) (*model.CommandResponse, *model.AppError) {
	split := strings.Fields(args.Command)
	command := split[0]
	action := "help"
	if len(split) > 1 {
		action = split[1]
	}

	if command == "/e2ee" {
		return &model.CommandResponse{}, nil
	}
	if action == "help" {
		p.PostCommandResponse(args, helpTextHeader+helpText)
		return &model.CommandResponse{}, nil
	}
	if action == "show_backup" {
		appErr := p.ShowGPGBackup(args)
		if appErr != nil {
			return &model.CommandResponse{}, nil
		}
	}
	return &model.CommandResponse{}, &model.AppError{Message: fmt.Sprintf("unknown command %v", action)}
}
