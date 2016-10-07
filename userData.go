package main

import (
	"fmt"
	"strings"
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
	uid := strings.Join(data.UID, ",")
	password := strings.Join(data.UserPassword, ",")
	uidNumber := strings.Join(data.UIDNumber, ",")
	gidNumber := strings.Join(data.GIDNumber, ",")
	homeDirectory := strings.Join(data.HomeDirectory, ",")
	extraFields := ""
	if len(data.Quota) != 0 {
		extraFields = "userdb_quota_rule=*:storage=" + data.Quota[0]
	}
	if len(uid) < 4 || len(password) < 4 || len(uidNumber) < 4 || len(gidNumber) < 4 || len(homeDirectory) < 4 {
		return &UserData{Err: fmt.Errorf("Incomplete data for uid: %s\n.  Skipping", uid)}
	}
	return &UserData{uid, password, uidNumber, gidNumber, homeDirectory, extraFields, nil}
}

func (u *UserData) passwd() string {
	return fmt.Sprintf("%s:%s:%s:%s::%s::%s\n", u.Email, u.Password, u.UID, u.GID, u.HomeDirectory, u.ExtraFields)
}
