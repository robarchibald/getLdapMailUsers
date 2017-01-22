package main

import (
	"fmt"
)

type UserData struct {
	Email       string
	Password    string
	UID         string
	GID         string
	MailFolder  string
	ExtraFields string
	Err         error
}

type ldapData struct {
	UID           []string
	UserPassword  []string
	UIDNumber     []string
	GIDNumber     []string
	HomeDirectory []string
	MailFolder    []string
	MailQuota     []string
}

func newUserData(data *ldapData) *UserData {
	if len(data.UID) != 1 || len(data.UserPassword) != 1 {
		return &UserData{Err: fmt.Errorf("invalid ldap record: %v", data)}
	}
	var extraFields, uidNumber, gidNumber, mailFolder string
	if len(data.GIDNumber) != 0 {
		gidNumber = data.GIDNumber[0]
	}
	if len(data.UIDNumber) != 0 {
		uidNumber = data.UIDNumber[0]
	}
	if len(data.HomeDirectory) != 0 {
		mailFolder = data.HomeDirectory[0]
	}
	if len(data.MailFolder) != 0 {
		mailFolder = data.MailFolder[0]
	}
	if len(data.MailQuota) != 0 {
		extraFields = "userdb_quota_rule=*:storage=" + data.MailQuota[0]
	}
	return &UserData{data.UID[0], data.UserPassword[0], uidNumber, gidNumber, mailFolder, extraFields, nil}
}

func (u *UserData) passwd() string {
	return fmt.Sprintf("%s:%s:%s:%s::%s::%s\n", u.Email, u.Password, u.UID, u.GID, u.MailFolder, u.ExtraFields)
}
