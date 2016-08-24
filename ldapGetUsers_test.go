package main

import (
	"bytes"
	"github.com/robarchibald/onedb"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"
)

func TestUpdateUserData(t *testing.T) {
	clean("testData/passwd_e2e*")
	clean("testData/postfix*")

	data := []ldapData{ldapData{UID: []string{"test@example.com"}, UserPassword: []string{"password"}, UIDNumber: []string{"1001"}, GIDNumber: []string{"10001"}, HomeDirectory: []string{"homeDirectory"}},
		ldapData{UID: []string{"test2@example2.com"}, UserPassword: []string{"password2"}, UIDNumber: []string{"1002"}, GIDNumber: []string{"10002"}, HomeDirectory: []string{"homeDirectory2"}}}
	db := onedb.NewMock(nil, nil, data)

	l := &LdapGetUsers{DovecotPasswdPath: "testData/passwd_e2e", PostfixVirtualMailboxDomainsPath: "testData/postfix_vmd", PostfixVirtualMailboxRecipientsPath: "testData/postfix_vmr"}
	l.updateUserData(db)
}

func TestGetUsers(t *testing.T) {
	data := []ldapData{ldapData{UID: []string{"test@example.com"}, UserPassword: []string{"password"}, UIDNumber: []string{"1001"}, GIDNumber: []string{"10001"}, HomeDirectory: []string{"homeDirectory"}},
		ldapData{UID: []string{"test2@example2.com"}, UserPassword: []string{"password2"}, UIDNumber: []string{"1002"}, GIDNumber: []string{"10002"}, HomeDirectory: []string{"homeDirectory2"}}}
	db := onedb.NewMock(nil, nil, data)

	l := &LdapGetUsers{}
	if users := l.getUsers(db); len(users) != 2 || users[0].Email != "test@example.com" || users[0].Password != "password" || users[0].UID != "1001" || users[0].GID != "10001" || users[0].HomeDirectory != "homeDirectory" ||
		users[1].Email != "test2@example2.com" || users[1].Password != "password2" || users[1].UID != "1002" || users[1].GID != "10002" || users[1].HomeDirectory != "homeDirectory2" {
		t.Error("expected to get expected user", users)
	}
}

func TestWritePasswdFile(t *testing.T) {
	clean("testData/passwd_basic*")

	data := []UserData{UserData{Email: "test@example.com",
		Password:      "password",
		UID:           "Uid",
		GID:           "Gid",
		HomeDirectory: "homeDirectory",
		ExtraFields:   "extraFields"}}
	writePasswdFile(data, "testData/passwd_basic")
	file, _ := ioutil.ReadFile("testData/passwd_basic")
	if string(file) != data[0].passwd() {
		t.Error("expected file to match passwd", string(file), data[0].passwd())
	}
}

func TestWriteIfChanged(t *testing.T) {
	clean("testData/hello*")

	var b bytes.Buffer
	b.WriteString("hello")
	writeIfChanged(b, "testData/hello")                       // write data
	writeIfChanged(b, "testData/hello")                       // no change, no write
	_, err := writeIfChanged(b, "testData/?&^%$#@!!)(*&\\/)") // invalid filename
	if err == nil {
		t.Error("expected error due to invalid filename")
	}
}

func TestWriteDomainsFile(t *testing.T) {
	clean("testData/domains")
	data := []UserData{UserData{Email: "test@example.com"}, UserData{Email: "test@example2.com"}}
	err := writeDomainsFile(data, "testData/domains", "postmap")
	if err == nil {
		t.Error("expected error since postmap command doesn't exist")
	}

	err = writeDomainsFile(data, "testData/domains", "postmap")
	if err != nil {
		t.Error("expected success since there was no change")
	}
}

func TestGetDomains(t *testing.T) {
	data := []UserData{UserData{Email: "test@example.com"}, UserData{Email: "test@example2.com"}}
	expected := "example.com\texample.com\nexample2.com\texample2.com\n"
	if b := getDomains(data); b.String() != expected {
		t.Error("expected example.com and example2.com")
	}
}

func TestWriteRecipientsFile(t *testing.T) {
	clean("testData/recipients")
	data := []UserData{UserData{Email: "test@example.com"}, UserData{Email: "test@example2.com"}}
	err := writeRecipientsFile(data, "testData/recipients", "postmap")
	if err == nil {
		t.Error("expected error since postmap command doesn't exist")
	}

	err = writeRecipientsFile(data, "testData/recipients", "postmap")
	if err != nil {
		t.Error("expected success since there was no change")
	}
}

func TestGetRecipients(t *testing.T) {
	data := []UserData{UserData{Email: "test@example.com"}, UserData{Email: "test@example2.com"}}
	expected := "test@example.com\ttest@example.com\ntest@example2.com\ttest@example2.com\n"
	if b := getRecipients(data); b.String() != expected {
		t.Error("expected valid recipients list")
	}
}

func TestCleanup(t *testing.T) {
	cleanup("testData/hello", 48)        // expect nothing to be removed since it's newer than 48 hours
	cleanup("testData/passwd_basic", -1) // new file removed
	if _, err := os.Stat("testData/passwd_basic"); os.IsExist(err) {
		t.Error("expected passwd_basic file to be removed")
	}
}

func TestCopyFileContents(t *testing.T) {
	cErr := copyFileContents("testData/hello", "testData/hello1")
	if _, err := os.Stat("testData/hello1"); cErr != nil || err != nil {
		t.Error("expected file to exist", cErr, err)
	}

	cErr = copyFileContents("testData/?&^%$#@!!)(*&\\/)", "testData/hello")
	if cErr == nil {
		t.Error("expected copy to fail due to invalid filename")
	}

	cErr = copyFileContents("testData/hello", "testData/?&^%$#@!!)(*&\\/)")
	if cErr == nil {
		t.Error("expected copy to fail due to invalid filename")
	}
}

func clean(searchglob string) {
	if _, err := os.Stat("testData"); os.IsNotExist(err) {
		os.Mkdir("testData", 755)
	}
	matches, _ := filepath.Glob(searchglob)
	for _, file := range matches {
		os.Remove(file)
	}
}
