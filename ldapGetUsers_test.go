package main

import (
	"bytes"
	"github.com/pkg/errors"
	"github.com/robarchibald/command"
	"github.com/robarchibald/onedb"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"
)

func TestUpdateUserData(t *testing.T) {
	clean("testData/passwd_e2e*")
	clean("testData/postfix*")

	data := []ldapData{ldapData{UID: []string{"test@example.com"}, UserPassword: []string{"password"}, UIDNumber: []string{"1001"}, GIDNumber: []string{"10001"}, MailFolder: []string{"MailFolder"}},
		ldapData{UID: []string{"test2@example2.com"}, UserPassword: []string{"password2"}, UIDNumber: []string{"1002"}, GIDNumber: []string{"10002"}, MailFolder: []string{"MailFolder2"}}}
	db := onedb.NewMock(nil, nil, data)

	l := &LdapGetUsers{DovecotPasswdPath: "testData/passwd_e2e", PostfixVirtualMailboxDomainsPath: "testData/postfix_vmd", PostfixVirtualMailboxRecipientsPath: "testData/postfix_vmr"}
	l.updateUserData(db)
}

func TestGetUsers(t *testing.T) {
	data := []ldapData{ldapData{UID: []string{"test@example.com"}, UserPassword: []string{"password"}, UIDNumber: []string{"1001"}, GIDNumber: []string{"10001"}, MailFolder: []string{"MailFolder"}},
		ldapData{UID: []string{"test2@example2.com"}, UserPassword: []string{"password2"}, UIDNumber: []string{"1002"}, GIDNumber: []string{"10002"}, MailFolder: []string{"MailFolder2"}}}
	db := onedb.NewMock(nil, nil, data)

	l := &LdapGetUsers{}
	if users := l.getUsers(db); len(users) != 2 || users[0].Email != "test@example.com" || users[0].Password != "password" || users[0].UID != "1001" || users[0].GID != "10001" || users[0].MailFolder != "MailFolder" ||
		users[1].Email != "test2@example2.com" || users[1].Password != "password2" || users[1].UID != "1002" || users[1].GID != "10002" || users[1].MailFolder != "MailFolder2" {
		t.Error("expected to get expected user", users)
	}
}

func TestWritePasswdFile(t *testing.T) {
	clean("testData/passwd_basic*")

	data := []UserData{UserData{Err: errors.New("error")}, UserData{Email: "test@example.com",
		Password:    "password",
		UID:         "Uid",
		GID:         "Gid",
		MailFolder:  "MailFolder",
		ExtraFields: "extraFields"}}
	writePasswdFile(data, "testData/passwd_basic")
	file, _ := ioutil.ReadFile("testData/passwd_basic")
	if string(file) != data[1].passwd() {
		t.Error("expected file to match passwd", string(file), data[1].passwd())
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
	clean("testData/domains*")
	domains := []string{"example.com", "example2.com"}
	err := writeDomainsFile(domains, "testData/domains", "postmap")
	if err == nil {
		t.Error("expected error since postmap command doesn't exist")
	}

	err = writeDomainsFile(domains, "testData/domains", "postmap")
	if err != nil {
		t.Error("expected success since there was no change")
	}
}

func TestRestartOpenDkim(t *testing.T) {
	command.SetMock(&command.MockShellCmd{CombinedOutputErr: errors.New("failed")})
	if err := restartOpenDKIM(); err == nil {
		t.Error("expected error")
	}

	command.SetMock(&command.MockShellCmd{})
	if err := restartOpenDKIM(); err != nil {
		t.Error("expected success", err)
	}
}

func TestWriteDkimTables(t *testing.T) {
	clean("testData/KeyTable*")
	clean("testData/SigningTable*")
	command.SetMock(&command.MockShellCmd{CombinedOutputErr: errors.New("failed")})
	err := writeDkimTables([]string{"example.com", "example2.com"}, "testData/KeyTable", "testData/SigningTable", "/my/folder")
	if err == nil {
		t.Error("expected error restarting service")
	}

	err = writeDkimTables([]string{"example.com", "example2.com"}, "testData/KeyTable", "testData/SigningTable", "/my/folder")
	if err != nil {
		t.Error("expected success since there was no change", err)
	}
}

func TestGetKeyTable(t *testing.T) {
	buffer := getKeyTable([]string{"example.com", "example2.com"}, "/my/folder")
	expected := "example.com example.com:mail:/my/folder/example.com/mail.private\nexample2.com example2.com:mail:/my/folder/example2.com/mail.private\n"
	if buffer.String() != expected {
		t.Error("expected matching KeyTable", buffer.String())
	}
}

func TestGetSigningTable(t *testing.T) {
	buffer := getSigningTable([]string{"example.com", "example2.com"})
	expected := "*@example.com example.com\n*@example2.com example2.com\n"
	if buffer.String() != expected {
		t.Error("expected matching SigningTable", buffer.String())
	}
}

func TestGetDomainsList(t *testing.T) {
	data := []UserData{UserData{Err: errors.New("error")}, UserData{Email: "test@example.com"}, UserData{Email: "test@example2.com"}}
	if b := getDomainsList(data); len(b) != 2 || b[0] != "example.com" || b[1] != "example2.com" {
		t.Error("expected example.com and example2.com", b)
	}
}

func TestGetDomainsFile(t *testing.T) {
	expected := "example.com\texample.com\nexample2.com\texample2.com\n"
	if b := getDomainsFile([]string{"example.com", "example2.com"}); b.String() != expected {
		t.Error("expected example.com and example2.com")
	}
}

func TestGenerateKeys(t *testing.T) {
	command.SetMock(&command.MockShellCmd{})
	if err := generateKeys([]string{"example.com", "example1.com"}, "testData"); err != nil {
		t.Error("expected success")
	}

	command.SetMock(&command.MockShellCmd{RunErr: errors.New("fail")})
	if err := generateKeys([]string{"example.com", "example1.com"}, "testData"); err == nil {
		t.Error("expected error")
	}
}

func TestCreateFolder(t *testing.T) {
	clean("newFolder")
	if err := createFolder("newFolder"); err != nil {
		t.Error("expected success")
	}

	if err := createFolder("newFolder"); err != nil {
		t.Error("expected success")
	}
}

func TestGenerateKey(t *testing.T) {
	command.SetMock(&command.MockShellCmd{RunErr: errors.New("failed")})
	if err := generateKey("example.com", "."); err == nil {
		t.Error("expected error")
	}

	command.SetMock(&command.MockShellCmd{})
	if err := generateKey("example.com", "."); err != nil {
		t.Error("expected success")
	}
}

func TestWriteRecipientsFile(t *testing.T) {
	clean("testData/recipients*")
	command.SetMock(&command.MockShellCmd{RunErr: errors.New("failed")})
	data := []UserData{UserData{Email: "test@example.com"}, UserData{Email: "test@example2.com"}}
	err := writeRecipientsFile(data, "testData/recipients", "postmap")
	if err == nil {
		t.Error("expected error running postmap command")
	}

	err = writeRecipientsFile(data, "testData/recipients", "postmap")
	if err != nil {
		t.Error("expected success since there was no change")
	}
}

func TestGetRecipients(t *testing.T) {
	data := []UserData{UserData{Err: errors.New("failed")}, UserData{Email: "test@example.com"}, UserData{Email: "test@example2.com"}}
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
