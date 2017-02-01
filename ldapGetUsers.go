package main

import (
	"bytes"
	"fmt"
	"github.com/pkg/errors"
	"github.com/robarchibald/command"
	"github.com/robarchibald/configReader"
	"github.com/robarchibald/onedb"
	"gopkg.in/ldap.v2"
	"io"
	"io/ioutil"
	"log"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

type LdapGetUsers struct {
	LdapServer                          string
	LdapPort                            string
	LdapBindDn                          string
	LdapPassword                        string
	LdapBaseDn                          string
	LdapQueryFilter                     string
	DovecotPasswdPath                   string
	PostfixVirtualMailboxAliasesPath    string
	PostfixVirtualMailboxDomainsPath    string
	PostfixVirtualMailboxRecipientsPath string
	PostmapPath                         string
	DKIMSigningTable                    string
	DKIMKeyTable                        string
	DKIMKeysFolder                      string
}

func main() {
	l := LdapGetUsers{}
	configReader.ReadFile("ldapGetUsers.conf", &l)
	port, err := strconv.Atoi(l.LdapPort)
	if err != nil {
		log.Fatal(err)
	}
	db, err := onedb.NewLdap(l.LdapServer, port, l.LdapBindDn, l.LdapPassword)
	if err != nil {
		log.Fatal(err)
	}
	if err := l.updateUserData(db); err != nil {
		log.Fatal(err)
	}
}

func (l *LdapGetUsers) updateUserData(db onedb.DBer) error {
	defer db.Close()

	users := l.getUsers(db)
	if err := writePasswdFile(users, l.DovecotPasswdPath); err != nil {
		return err
	}
	domains := getDomainsList(users)
	if err := writeDomainsFile(domains, l.PostfixVirtualMailboxDomainsPath, l.PostmapPath); err != nil {
		return err
	}
	if err := writeDkimTables(domains, l.DKIMKeyTable, l.DKIMSigningTable, l.DKIMKeysFolder); err != nil {
		return err
	}
	if err := writeRecipientsFile(users, l.PostfixVirtualMailboxRecipientsPath, l.PostmapPath); err != nil {
		return err
	}
	return nil
}

func (l *LdapGetUsers) getUsers(db onedb.DBer) []UserData {
	req := ldap.NewSearchRequest(l.LdapBaseDn, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false, l.LdapQueryFilter, []string{"uid", "userPassword", "uidNumber", "gidNumber", "homeDirectory", "mailFolder", "mailQuota"}, nil)
	data := []ldapData{}
	db.QueryStruct(req, &data)
	users := []UserData{}
	for _, item := range data {
		users = append(users, *newUserData(&item))
	}
	return users
}

func writePasswdFile(userData []UserData, filename string) error {
	_, err := writeIfChanged(getPasswd(userData), filename)
	return err
}

func getPasswd(userData []UserData) bytes.Buffer {
	var buffer bytes.Buffer
	for _, item := range userData {
		if item.Err != nil {
			continue
		}
		buffer.WriteString(item.passwd())
	}
	return buffer
}

func writeIfChanged(buffer bytes.Buffer, filename string) (bool, error) {
	if fileChanged(filename, buffer) {
		if err := ioutil.WriteFile(filename, buffer.Bytes(), 0400); err != nil {
			return false, err
		}
		fmt.Println("Updated: " + filename)
		copyFileContents(filename, fmt.Sprintf("%s_%s", filename, time.Now().Format("20060102-150405")))
		cleanup(filename+"_*", 48)
		return true, nil
	}
	return false, nil
}

func fileChanged(filename string, buffer bytes.Buffer) bool {
	if data, err := ioutil.ReadFile(filename); err == nil && string(data) == buffer.String() {
		return false
	}
	return true
}

func rebuildHash(filename string, postmapPath string) error {
	cmd := command.Command(postmapPath, "hash:"+filename)
	return cmd.Run()
}

func writeDomainsFile(domains []string, virtualDomainsFile string, postmapPath string) error {
	buffer := getDomainsFile(domains)
	if changed, _ := writeIfChanged(buffer, virtualDomainsFile); changed {
		return rebuildHash(virtualDomainsFile, postmapPath)
	}
	return nil
}

func restartOpenDKIM() error {
	output, err := command.Command("/usr/sbin/service", "opendkim", "restart").CombinedOutput()
	if err != nil {
		return errors.Wrap(err, "Unable to restart opendkim server. "+string(output))
	}
	return nil
}

func writeDkimTables(domains []string, keyTableFile, signingTableFile, keysFolder string) error {
	buffer := getKeyTable(domains, keysFolder)
	ktChanged, err := writeIfChanged(buffer, keyTableFile)
	if err != nil {
		return err
	}
	buffer = getSigningTable(domains)
	stChanged, err := writeIfChanged(buffer, signingTableFile)
	if err != nil {
		return err
	}
	if ktChanged || stChanged {
		return restartOpenDKIM()
	}
	return nil
}

func getDomainsList(userData []UserData) []string {
	domains := make(map[string]struct{})
	for _, item := range userData {
		if item.Err != nil {
			continue
		}
		separator := strings.Index(item.Email, "@")
		if separator != -1 {
			domain := item.Email[separator+1 : len(item.Email)]
			domains[domain] = struct{}{}
		}
	}

	domainArr := make([]string, len(domains))
	i := 0
	for domain := range domains {
		domainArr[i] = domain
		i++
	}
	sort.Strings(domainArr)
	return domainArr
}

func getDomainsFile(domains []string) bytes.Buffer {
	var buffer bytes.Buffer
	for _, domain := range domains {
		buffer.WriteString(domain + "\t" + domain + "\n")
	}
	return buffer
}

func getKeyTable(domains []string, keysFolder string) bytes.Buffer {
	var buffer bytes.Buffer
	for _, domain := range domains {
		buffer.WriteString(fmt.Sprintf("%s %s:mail:%s\n", domain, domain, path.Join(keysFolder, domain+".private")))
	}
	return buffer
}

func getSigningTable(domains []string) bytes.Buffer {
	var buffer bytes.Buffer
	for _, domain := range domains {
		buffer.WriteString(fmt.Sprintf("*@%s %s\n", domain, domain))
	}
	return buffer
}

func writeRecipientsFile(userData []UserData, virtualRecipientsFile string, postmapPath string) error {
	buffer := getRecipients(userData)
	if changed, _ := writeIfChanged(buffer, virtualRecipientsFile); changed {
		return rebuildHash(virtualRecipientsFile, postmapPath)
	}
	return nil
}

func getRecipients(userData []UserData) bytes.Buffer {
	var buffer bytes.Buffer
	for _, item := range userData {
		if item.Err != nil {
			continue
		}
		buffer.WriteString(item.Email)
		buffer.WriteString("\t")
		buffer.WriteString(item.Email)
		buffer.WriteString("\n")
	}
	return buffer
}

func cleanup(searchglob string, hoursToKeep int) {
	matches, _ := filepath.Glob(searchglob)
	now := time.Now()
	for _, file := range matches {
		info, err := os.Stat(file)
		if err == nil && now.Sub(info.ModTime()) > time.Hour*time.Duration(hoursToKeep) {
			os.Remove(file)
		}
	}
}

func copyFileContents(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer func() {
		cerr := out.Close()
		if err == nil {
			err = cerr
		}
	}()
	io.Copy(out, in)
	err = out.Sync()
	return err
}
