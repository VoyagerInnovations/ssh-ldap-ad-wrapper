package main

import "log"
import "fmt"
import "gopkg.in/ldap.v2"
import "os"
//import "github.com/spf13/pflag"

var uri = "192.168.32.113"
var port = 389
var user = ""
var pass = ""
var base_search = "dc=corp,dc=example,dc=com"
var pubkey_property = "altSecurityIdentities"

func search_pubkey(uname string) {
	l, err := ldap.Dial("tcp", fmt.Sprintf("%s:%d", uri, port))
	if err != nil {
		log.Fatal(err)
	}
	defer l.Close()


        err = l.Bind(user, pass)
        if err != nil {
                log.Fatal(err)
        }

	searchRequest := ldap.NewSearchRequest(
		base_search,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		"(sAMAccountName=" + uname  +  ")", // The filter to apply
		[]string{pubkey_property},                    // A list attributes to retrieve
		nil,
	)

	sr, err := l.Search(searchRequest)
	if err != nil {
		log.Fatal(err)
	}

	for _, entry := range sr.Entries {
		fmt.Printf("%v\n",  entry.GetAttributeValue(pubkey_property))
	}
}

func main() {
	if len(os.Args) > 1  {
		search_pubkey(os.Args[1])
	}
}
