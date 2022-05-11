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

type Foo struct {
	Directs []*Foo `ldap:"directReports"`
	Manager *Foo   `ldap:"manager"`
	Type    string `ldap:"employeeType"`
	Name    string `ldap:"displayName"`
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
			// Show how to ignore hostname validation
			InsecureSkipVerify: true,
		},
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

	f := &Foo{}
	err = z.Populate(who, 40, f)
	if err != nil {
		panic(err)
	}

	pretty.Print(f)
}
