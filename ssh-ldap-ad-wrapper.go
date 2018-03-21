package main

import (
	"os"
        "log"
        "fmt"
        "gopkg.in/ldap.v2"
        "crypto/tls"
        "crypto/x509"
        "io/ioutil" 
        "bufio"
        "strings"
)

var ldap_config_file = "/etc/nslcd.conf"
var pubkey_property = "altSecurityIdentities"

func main() {

        if len(os.Args) > 1  {

		var l  *ldap.Conn
		var conf *tls.Config
       		var uname = os.Args[1] 
                var user string
                var pass string
                var base_search string
                var server_rootca string
		var uris [2]string
		var uris_cnt int64

                file, err := os.Open(ldap_config_file)
                if err != nil {
                        log.Fatal(err)
                }
                defer file.Close()
        
                scanner := bufio.NewScanner(file)
                for scanner.Scan() {
                        
                        if (!strings.HasPrefix(scanner.Text(),"#")) {

                                if (strings.HasPrefix(scanner.Text(), "uri")) {
                                        s := strings.Split(scanner.Text(), " ")
					ss := strings.Split(s[1],"//")
                                        uris[uris_cnt] = ss[1]
					uris_cnt++
                                        continue
                                }

                                if (strings.HasPrefix(scanner.Text(), "base")) {
                                        s := strings.Split(scanner.Text(), " ") 
                                        base_search = s[1]
                                        continue 
                                }

                                if (strings.HasPrefix(scanner.Text(), "binddn")) {
                                        s := strings.Split(scanner.Text(), " ") 
                                        user = s[1]
                                        continue 
                                }

                                if (strings.HasPrefix(scanner.Text(), "bindpw")) {
                                        s := strings.Split(scanner.Text(), " ") 
                                        pass = s[1]
                                        continue 
                                }

                                if (strings.HasPrefix(scanner.Text(), "tls_cacertfile")) {
                                        s := strings.Split(scanner.Text(), " ") 
                                        server_rootca = s[1]
                                        continue 
                                }
                        }
        	}
 
                if err := scanner.Err(); err != nil {
                	log.Fatal(err)
                }


                //Load CA Cert

                cert, err := ioutil.ReadFile(server_rootca)
                if err != nil {
                        log.Fatalf("Couldn't load file", err)
                }
                certPool := x509.NewCertPool()
                certPool.AppendCertsFromPEM(cert)

                // Connect

		for _, uri := range uris {
			ss := strings.Split(uri,":")
                	conf = &tls.Config{
                        	RootCAs: certPool,
                        	InsecureSkipVerify: false,
                        	ServerName: ss[0],
                	}

			l, err = ldap.Dial("tcp", uri)
			if err == nil {
                        	break
                	}
		}

		if err != nil {
                        log.Fatal(err)
                }

                defer l.Close()

                err = l.StartTLS(conf)
                        if err != nil {
                        log.Fatal(err)
                }

                err = l.Bind(user, pass)
                if err != nil {
                        log.Fatal(err)
                }

                // Search
                searchRequest := ldap.NewSearchRequest(
                        base_search,
                        ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
                        "(sAMAccountName=" + uname  +  ")", 
                        []string{pubkey_property},
                        nil,
                )

                sr, err := l.Search(searchRequest)
                if err != nil {
                        log.Fatal(err)
                }

                // Display
                for _, entry := range sr.Entries {
                        fmt.Printf("%v\n",  entry.GetAttributeValue(pubkey_property))
                }
        }
}
