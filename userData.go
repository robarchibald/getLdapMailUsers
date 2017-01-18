package main

import (
	"fmt"
)

type UserData struct {
	Email         string
	Password      string
	UID           string
	GID           string
	HomeDirectory string
	ExtraFields   string
	Err           error
}

type ldapData struct {
	UID           []string
	UserPassword  []string
	UIDNumber     []string
	GIDNumber     []string
	HomeDirectory []string
	Quota         []string
}

func newUserData(data *ldapData) *UserData {
	if len(data.UID) != 1 || len(data.UserPassword) != 1 || len(data.UIDNumber) != 1 || len(data.GIDNumber) != 1 || len(data.HomeDirectory) != 1 {
		return &UserData{Err: fmt.Errorf("invalid ldap record: %v", data)}
	}
	extraFields := ""
	if len(data.Quota) != 0 {
		extraFields = "userdb_quota_rule=*:storage=" + data.Quota[0]
	}
	return &UserData{data.UID[0], data.UserPassword[0], data.UIDNumber[0], data.GIDNumber[0], data.HomeDirectory[0], extraFields, nil}
}

func (u *UserData) passwd() string {
	return fmt.Sprintf("%s:%s:%s:%s::%s::%s\n", u.Email, u.Password, u.UID, u.GID, u.HomeDirectory, u.ExtraFields)
}
