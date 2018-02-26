package main

import (

        "log"
        "fmt"
        "gopkg.in/ldap.v2"
        "os"
        "crypto/tls"
        "crypto/x509"
        "io/ioutil" 
        "bufio"
        "strings"
        "strconv"

)

var ldap_config_file = "/etc/ssh-ldap-ad.conf"

func main() {

        if len(os.Args) > 1  {
        
                var uri string
                var hostname string
                var port int64
                var user string
                var pass string
                var base_search string
                var pubkey_property string
                var server_rootca string
                var uname = os.Args[1]


                file, err := os.Open(ldap_config_file)
                if err != nil {
                        log.Fatal(err)
                }
                defer file.Close()
        
                scanner := bufio.NewScanner(file)
                for scanner.Scan() {
                        
                        if (!strings.HasPrefix(scanner.Text(),"#")) {

                                if (strings.HasPrefix(scanner.Text(), "ip")) {
                                        s := strings.Split(scanner.Text(), " ") 
                                        uri = s[1]
                                        continue 
                                }

                                if (strings.HasPrefix(scanner.Text(), "port")) {
                                        s := strings.Split(scanner.Text(), " ") 
                                        p := s[1]
                                        port, err = strconv.ParseInt(p, 10, 32)
                                        continue 
                                }

                                if (strings.HasPrefix(scanner.Text(), "hostname")) {
                                        s := strings.Split(scanner.Text(), " ") 
                                        hostname = s[1]
                                        continue 
                                }

                                if (strings.HasPrefix(scanner.Text(), "base_search")) {
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

                                if (strings.HasPrefix(scanner.Text(), "pubkey_property")) {
                                        s := strings.Split(scanner.Text(), " ") 
                                        pubkey_property = s[1]
                                        continue 
                                }
                                
                                if (strings.HasPrefix(scanner.Text(), "server_rootca")) {
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

                conf := &tls.Config{
                        RootCAs: certPool,
                        InsecureSkipVerify: false,
                        ServerName: hostname,
                }

                // Connect
                l, err := ldap.Dial("tcp", fmt.Sprintf("%s:%d", uri, port))
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
