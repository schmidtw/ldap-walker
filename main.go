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

	"github.com/kr/pretty"
	"github.com/schmidtw/ldap-walker/zapper"
)

type Mgr struct {
	Person string `ldap:"sAMAccountName"`
}

type Mgr2 struct {
	Person string
}

type Foo struct {
	Person [1]string `ldap:"sAMAccountName"`
	Other  string
	//Dogs   string `ldap:"dogs"`
	//DirectDNs []string `ldap:"directReports"`
	ManagerDN string   `ldap:"manager"`
	Manager   Mgr      `ldap:"manager"`
	Manager1  *Foo     `ldap:"manager"`
	Managers  []Foo    `ldap:"manager"`
	Managers1 []*Foo   `ldap:"manager"`
	Managers2 [1]*Foo  `ldap:"manager"`
	Managers3 [1]Mgr   `ldap:"manager"`
	Managers4 [0]Mgr2  `ldap:"manager"`
	Keys      []string `ldap:"?"`
	//Directs  []Foo `ldap:"directReports"`
	//Directs1 []Mgr `ldap:"directReports"`
}

func main() {

	port, err := strconv.Atoi(os.Getenv("ZAPPER_PORT")) // 3269
	if err != nil {
		fmt.Printf("Error: ZAPPER_PORT needs to be a port number ... %#v\n", err)
		return
	}

	z := &zapper.Zapper{
		BaseDN:   os.Getenv("ZAPPER_BASE"),
		User:     os.Getenv("ZAPPER_USER"),
		Password: os.Getenv("ZAPPER_PASSWORD"),
		Hostname: os.Getenv("ZAPPER_HOSTNAME"),
		Port:     port,
		TLSConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
		// Generally, keep this list small to speed things up for larger trees
		/*
			Attributes: []string{
				zapper.AttrDirectReports, // Needed to walk the tree
				zapper.AttrDisplayName,   // Everything else is really optional
				zapper.AttrTitle,
				zapper.AttrNTID,
				zapper.AttrEmployeeType,
				zapper.AttrEmail,
				zapper.AttrMailNickname,
				zapper.AttrUserPrincipalName,
			},
		*/
	}

	err = z.Connect()
	if err != nil {
		panic(err)
	}
	defer z.Close()

	if len(os.Args) < 1 {
		fmt.Printf("A user (email) to build the tree under is needed as input.\n")
		return
	}

	who, err := z.FindByEmail(os.Args[1])
	if err != nil {
		panic(err)
	}
	if who == "" {
		fmt.Printf("User not found.")
		return
	}

	person, err := z.SeeFull(who)
	pretty.Print(person)

	f := Foo{}
	err = z.Populate(who, 4, &f)
	if err != nil {
		panic(err)
	}

	fmt.Printf("\n\nFoo:\n")
	pretty.Print(f)
	fmt.Printf("\n\n")
	/*
		emp, err := z.WalkTree(who)
		if err != nil {
			panic(err)
		}

		emp.Directs = []*zapper.Employee{}

		d, err := yaml.Marshal(&emp)
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
	*/
}
