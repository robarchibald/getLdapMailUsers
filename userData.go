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
	UID          []string
	UserPassword []string
	UIDNumber    []string
	GIDNumber    []string
	MailFolder   []string
	MailQuota    []string
}

func newUserData(data *ldapData) *UserData {
	if len(data.UID) != 1 || len(data.UserPassword) != 1 || len(data.UIDNumber) != 1 || len(data.GIDNumber) != 1 || len(data.MailFolder) != 1 {
		return &UserData{Err: fmt.Errorf("invalid ldap record: %v", data)}
	}
	extraFields := ""
	if len(data.MailQuota) != 0 {
		extraFields = "userdb_quota_rule=*:storage=" + data.MailQuota[0]
	}
	return &UserData{data.UID[0], data.UserPassword[0], data.UIDNumber[0], data.GIDNumber[0], data.MailFolder[0], extraFields, nil}
}

func (u *UserData) passwd() string {
	return fmt.Sprintf("%s:%s:%s:%s::%s::%s\n", u.Email, u.Password, u.UID, u.GID, u.MailFolder, u.ExtraFields)
}
