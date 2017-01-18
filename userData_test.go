package main

import (
	"testing"
)

func TestNewUserData(t *testing.T) {
	// failure
	data := ldapData{}
	c := newUserData(&data)
	if c.Err == nil {
		t.Error("expected error")
	}

	// success, no quota
	data = ldapData{[]string{"uid"}, []string{"password"}, []string{"uidnumber"}, []string{"gidnumber"}, []string{"homedir"}, nil}
	c = newUserData(&data)
	if c.Err != nil {
		t.Error("epxected success")
	}

	// success, with quota
	data = ldapData{[]string{"uid"}, []string{"password"}, []string{"uidnumber"}, []string{"gidnumber"}, []string{"homedir"}, []string{"10GB"}}
	c = newUserData(&data)
	if c.Err != nil {
		t.Error("epxected success")
	}
}
