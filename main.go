/**
 *  Copyright (c) 2022  Weston Schmidt
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */
package main

import (
	"crypto/tls"
	"fmt"
	"os"
	"strconv"

	"github.com/go-ldap/ldap/v3"
	"gopkg.in/yaml.v2"
)

type Zapper struct {
	BaseDN     string //"DC=example,dc=com",
	User       string
	Password   string
	Hostname   string // ldap.example.com
	Port       int    // 3269
	l          *ldap.Conn
	Attributes []string
}

func (z *Zapper) Connect() error {
	// Often times folks don't have the right certificates for this server.
	l, err := ldap.DialTLS(
		"tcp",
		fmt.Sprintf("%s:%d", z.Hostname, z.Port),
		&tls.Config{
			InsecureSkipVerify: true,
		})
	if err != nil {
		return err
	}

	err = l.Bind(z.User, z.Password)
	if err != nil {
		defer l.Close()
		return err
	}

	z.l = l

	return nil
}

func (z *Zapper) Close() {
	if z.l != nil {
		z.l.Close()
	}
}

func (z *Zapper) GetNTID(ntid string) (*ldap.Entry, error) {
	req := &ldap.SearchRequest{
		BaseDN:       z.BaseDN,
		Scope:        ldap.ScopeWholeSubtree,
		DerefAliases: ldap.NeverDerefAliases,
		Filter:       fmt.Sprintf("(&(objectClass=user)(sAMAccountName=%s))", ldap.EscapeFilter(ntid)),
		Attributes:   z.Attributes,
	}

	res, err := z.l.Search(req)
	if err != nil {
		return nil, err
	}

	if len(res.Entries) != 1 {
		return nil, fmt.Errorf("Too many matching responses.")
	}

	return res.Entries[0], nil
}

func (z *Zapper) GetDN(dn string) (*ldap.Entry, error) {
	full, err := ldap.ParseDN(dn)
	if err != nil {
		return nil, err
	}

	// Split off the CN field but re-assemble the rest in order
	cn := "invalid"
	base := ""
	comma := ""
	for _, item := range full.RDNs {
		for _, sub := range item.Attributes {
			if sub.Type == "CN" {
				cn = sub.Value
			} else {
				base += comma + sub.Type + "=" + sub.Value
				comma = ","
			}
		}
	}

	req := &ldap.SearchRequest{
		BaseDN:       base,
		Scope:        ldap.ScopeWholeSubtree,
		DerefAliases: ldap.NeverDerefAliases,
		Filter:       fmt.Sprintf("(&(objectClass=user)(cn=%s))", ldap.EscapeFilter(cn)),
		Attributes:   z.Attributes,
	}

	res, err := z.l.Search(req)
	if err != nil {
		return nil, err
	}

	if len(res.Entries) != 1 {
		return nil, fmt.Errorf("Too many matching responses.")
	}

	return res.Entries[0], nil
}

type Employee struct {
	NTID         string     `yaml:"ntid,omitempty"`
	DisplayName  string     `yaml:"name,omitempty"`
	Title        string     `yaml:"title,omitempty"`
	EmployeeType string     `yaml:"-"`
	Directs      []Employee `yaml:"directs,omitempty"`
}

func GetManager(z *Zapper, dn string) (Employee, error) {
	who, err := z.GetDN(dn)
	if err != nil {
		return Employee{}, err
	}

	for _, attribute := range who.Attributes {
		switch attribute.Name {
		case "manager":
			return ProcessNode(z, attribute.Values[0], false)
		}
	}

	return Employee{}, nil
}

func ProcessNode(z *Zapper, dn string, directs bool) (Employee, error) {
	who, err := z.GetDN(dn)
	if err != nil {
		fmt.Printf("Error: %s\n", dn)
		return Employee{}, err
	}

	e := Employee{}

	for _, attribute := range who.Attributes {
		switch attribute.Name {
		case "displayName":
			e.DisplayName = attribute.Values[0]
		case "title":
			e.Title = attribute.Values[0]
		case "sAMAccountName":
			e.NTID = attribute.Values[0]
		case "employeeType":
			e.EmployeeType = attribute.Values[0]
		case "directReports":
			if directs {
				for _, direct := range attribute.Values {
					tmp, err := ProcessNode(z, direct, directs)
					if err != nil {
						fmt.Printf("Error: %s\n", direct)
						return Employee{}, err
					}

					// Ignore service users
					if "S" != tmp.EmployeeType && "R" != tmp.EmployeeType {
						e.Directs = append(e.Directs, tmp)
					}
				}
			}
		default:
		}
	}

	return e, nil
}

func main() {

	port, err := strconv.Atoi(os.Getenv("ZAPPER_PORT")) // 3269
	if err != nil {
		fmt.Printf("Error: ZAPPER_PORT needs to be a port number ... %#v\n", err)
		return
	}

	z := &Zapper{
		BaseDN:   os.Getenv("ZAPPER_BASE"),
		User:     os.Getenv("ZAPPER_USER"),
		Password: os.Getenv("ZAPPER_PASSWORD"),
		Hostname: os.Getenv("ZAPPER_HOSTNAME"),
		Port:     port,
		// Generally, keep this list small to speed things up for larger trees
		Attributes: []string{
			"displayName",    // Display form of the name:
			"title",          //
			"manager",        //
			"directReports",  //
			"sAMAccountName", // NTID

			/* Other common values
			"cn",             // common name
			"mail",              // email
			"employeeType",      // The employee type
			"userPrincipalName", // NTID@example.com
			"sn",                // surname
			"givenName",         // firstname
			*/
		},
	}

	err = z.Connect()
	if err != nil {
		panic(err)
	}
	defer z.Close()

	if len(os.Args) < 1 {
		fmt.Printf("A user (NTID) to build the tree under is needed as input.\n")
		return
	}

	who, err := z.GetNTID(os.Args[1])
	if err != nil {
		panic(err)
	}

	// Provide the manager of the person of interest to make going up
	// the tree easier.
	manager, err := GetManager(z, who.DN)
	if err != nil {
		panic(err)
	}

	emp, err := ProcessNode(z, who.DN, true)
	if err != nil {
		panic(err)
	}

	manager.Directs = append(manager.Directs, emp)

	d, err := yaml.Marshal(&manager)
	if err != nil {
		panic(err)
	}

	if 2 < len(os.Args) {
		file, err := os.Create(os.Args[2])
		if err != nil {
			panic(err)
		}
		defer file.Close()
		file.Write(d)
	} else {
		fmt.Printf("%s\n", string(d))
	}
}
