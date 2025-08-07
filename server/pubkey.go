package main

import (
	"crypto/elliptic"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
)

var ECCurve = elliptic.P256()

func StoreKeyPubKey(userID string) string {
	return fmt.Sprintf("pubkey:%s", userID)
}

func StoreBackupGPGKey(userID string) string {
	return fmt.Sprintf("backup_gpg:%s", userID)
}

type PubKey struct {
	Encr []byte `json:"encr"`
	Sign []byte `json:"sign"`
}

type ECPoint struct {
	x big.Int
	y big.Int
}

func (pt *ECPoint) Equals(o *ECPoint) bool {
	return pt.x.Cmp(&o.x) == 0 && pt.y.Cmp(&o.y) == 0
}

func validateECPoint(data []byte) *ECPoint {
	ECParams := ECCurve.Params()
	CL := ECParams.BitSize / 8
	if len(data) != 2*CL+1 {
		return nil
	}

	if data[0] != 0x04 {
		return nil
	}

	x := big.Int{}
	y := big.Int{}
	x.SetBytes(data[1:(CL + 1)])
	y.SetBytes(data[(CL + 1):])

	zero := big.NewInt(0)
	if x.Cmp(zero) == 0 || y.Cmp(zero) == 0 {
		return nil
	}

	N := ECParams.N
	if x.Cmp(N) >= 0 || y.Cmp(N) >= 0 {
		return nil
	}

	if !ECCurve.IsOnCurve(&x, &y) {
		return nil
	}

	NBytes := make([]byte, CL)
	N.FillBytes(NBytes)
	tx, ty := ECCurve.ScalarMult(&x, &y, NBytes)
	if tx.Cmp(zero) != 0 || ty.Cmp(zero) != 0 {
		return nil
	}
	return &ECPoint{x, y}
}

func (pubkey *PubKey) Validate() bool {
	encr := validateECPoint(pubkey.Encr)
	if encr == nil {
		return false
	}
	sign := validateECPoint(pubkey.Sign)
	if sign == nil {
		return false
	}
	return true
}

func (p *Plugin) GetUserPubKey(userID string) (*PubKey, error) {
	pubkeyJson, appErr := p.API.KVGet(StoreKeyPubKey(userID))
	if appErr != nil {
		return nil, appErr
	}

	if pubkeyJson == nil {
		return nil, nil
	}

	var pubkey PubKey
	err := json.Unmarshal(pubkeyJson, &pubkey)
	if err != nil {
		return nil, err
	}

	return &pubkey, nil
}

func (p *Plugin) SetUserPubKey(userID string, pk *PubKey) error {
	pubkey, err := json.Marshal(pk)
	if err != nil {
		return err
	}

	appErr := p.API.KVSet(StoreKeyPubKey(userID), pubkey)
	if appErr != nil {
		return errors.New(appErr.Error())
	}
	return nil
}

func (p *Plugin) HasUserPubKey(userID string) (bool, error) {
	pubkey, appErr := p.API.KVGet(StoreKeyPubKey(userID))
	if appErr != nil {
		return false, appErr
	}
	return pubkey != nil, nil
}

func (p *Plugin) GetChannelMembersWithoutKeys(chanID string) ([]string, error) {

	result := make([]string, 0)
	cfg := p.API.GetConfig()
	maxUsersPerTeam := *cfg.TeamSettings.MaxUsersPerTeam
	chanMembers, appErr := p.API.GetChannelMembers(chanID, 0, maxUsersPerTeam)
	if appErr != nil {
		return result, appErr
	}

	for _, member := range chanMembers {
		userID := member.UserId
		hasKey, appErr := p.HasUserPubKey(userID)
		if appErr != nil {
			return result, appErr
		}

		if hasKey {
			continue
		}
		user, appErr := p.API.GetUser(userID)
		if appErr != nil {
			return result, appErr
		}
		if user.DeleteAt != 0 {
			continue
		}
		result = append(result, userID)
	}
	return result, nil
}
