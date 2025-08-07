package main

import (
	"encoding/json"
	"fmt"
	"github.com/mattermost/mattermost/server/public/model"
	"github.com/mattermost/mattermost/server/public/plugin"
	"sync"
)

type ChanEncryptionMethod int

const (
	ChanEncryptionMethodNone ChanEncryptionMethod = 0
	ChanEncryptionMethodP2P  ChanEncryptionMethod = 1
)

func ChanEncryptionMethodKey(chanID string) string {
	return fmt.Sprintf("chanEncrMethod:%s", chanID)
}

func ChanEncryptionMethodString(m ChanEncryptionMethod) string {
	if m == ChanEncryptionMethodP2P {
		return "p2p"
	} else {
		return "none"
	}
}

func ChanEncryptionMethodFromString(s string) ChanEncryptionMethod {
	if s == "p2p" {
		return ChanEncryptionMethodP2P
	} else {
		return ChanEncryptionMethodNone
	}
}

type ChanEncrMethodDB struct {
	mutex sync.RWMutex
	API   plugin.API
}

func NewChanEncrMethodDB(api plugin.API) *ChanEncrMethodDB {
	return &ChanEncrMethodDB{
		mutex: sync.RWMutex{},
		API:   api,
	}
}

func (db *ChanEncrMethodDB) get(chanID string) ChanEncryptionMethod {
	db.mutex.RLock()
	defer db.mutex.RUnlock()

	method, appErr := db.API.KVGet(ChanEncryptionMethodKey(chanID))
	if method == nil || appErr != nil {
		return ChanEncryptionMethodNone
	}
	var ret ChanEncryptionMethod
	err := json.Unmarshal(method, &ret)
	if err != nil {
		return ChanEncryptionMethodNone
	}
	return ret
}

func (db *ChanEncrMethodDB) setIfDifferent(chanID string, newMethod ChanEncryptionMethod) (bool, *model.AppError) {
	db.mutex.Lock()
	defer db.mutex.Unlock()

	key := ChanEncryptionMethodKey(chanID)
	omJS, appErr := db.API.KVGet(key)
	if appErr != nil {
		return false, appErr
	}
	var oldMethod ChanEncryptionMethod
	if omJS == nil {
		oldMethod = ChanEncryptionMethodNone
	} else {
		err := json.Unmarshal(omJS, &oldMethod)
		if err != nil {
			return false, &model.AppError{}
		}
	}
	if oldMethod == newMethod {
		return false, nil
	}
	nmJS, _ := json.Marshal(newMethod)
	appErr = db.API.KVSet(key, nmJS)
	if appErr != nil {
		return false, appErr
	}
	return true, nil
}
