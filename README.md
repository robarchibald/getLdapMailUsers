# Get LDAP Mail Users
[![Build Status](https://travis-ci.org/EndFirstCorp/getLdapMailUsers.svg?branch=master)](https://travis-ci.org/EndFirstCorp/getLdapMailUsers) [![Coverage Status](https://coveralls.io/repos/github/EndFirstCorp/getLdapMailUsers/badge.svg?branch=master)](https://coveralls.io/github/EndFirstCorp/getLdapMailUsers?branch=master)

A Dovecot and Postfix configuration writer to keep users synchronized between LDAP and Email servers

## Getting Started
    go get https://github.com/robarchibald/getLdapMailUsers

 1. Update ldapGetUsers.conf with the following information for your system installation
	- LdapServer - address of your OpenLDAP server
	- LdapPort - OpenLDAP server port
	- LdapBindDn - Admin bind username
	- LdapPassword - Password for Admin bind username
	- LdapBaseDn - root path for search
	- LdapQueryFilter - query filter for user search
	- DovecotPasswdPath - Dovecot passwd-style user file
	- PostfixVirtualMailboxAliasesPath - Postfix virtual mailbox alias file
	- PostfixVirtualMailboxDomainsPath - Postfix virtual mailbox domains file
	- PostfixVirtualMailboxRecipientsPath - Postfix virtual mailbox recipients path
	- PostmapPath - Path to postmap command (usually /usr/sbin/postmap)
 2. Run getLdapMailUsers executable. Dovecot passwd, Postfix virtual mailbox alias, Postfix virtual mailbox domains, and Postfix virtual mailbox recipients files will be created