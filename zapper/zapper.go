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
package zapper

import (
	"crypto/tls"
	"fmt"
	"reflect"
	"strings"

	"github.com/go-ldap/ldap/v3"
)

const (
	attrDirectReports = "directReports"
	attrManager       = "manager"
)

type Zapper struct {
	BaseDN      string //"DC=example,dc=com",
	User        string
	Password    string
	Hostname    string // ldap.example.com
	Port        int    // 3269
	TLSConfig   *tls.Config
	l           *ldap.Conn
	personCache map[ldapCacheKey]*ldap.Entry
	attribCache map[string][]string
}

type ldapCacheKey struct {
	objType string
	dn      string
}

func NewZapper(BaseDN string, l *ldap.Conn) *Zapper {
	z := &Zapper{
		BaseDN: BaseDN,
		l:      l,
	}

	return z
}

func (z *Zapper) Connect() error {
	// Often times folks don't have the right certificates for this server.
	l, err := ldap.DialTLS(
		"tcp",
		fmt.Sprintf("%s:%d", z.Hostname, z.Port),
		z.TLSConfig,
	)
	if err != nil {
		return err
	}

	err = l.Bind(z.User, z.Password)
	if err != nil {
		defer l.Close()
		return err
	}

	z.l = l
	z.personCache = make(map[ldapCacheKey]*ldap.Entry)
	z.attribCache = make(map[string][]string)

	return nil
}

func (z *Zapper) Close() {
	if z.l != nil {
		z.l.Close()
	}
}

func (z *Zapper) FindByNTID(ntid string) (string, error) {
	return z.Find(fmt.Sprintf("(&(objectClass=user)(sAMAccountName=%s))", ldap.EscapeFilter(ntid)))
}

func (z *Zapper) FindByEmail(email string) (string, error) {
	return z.Find(fmt.Sprintf("(&(objectClass=user)(mail=%s))", ldap.EscapeFilter(email)))
}

func (z *Zapper) Find(filter string) (string, error) {
	req := &ldap.SearchRequest{
		BaseDN:       z.BaseDN,
		Scope:        ldap.ScopeWholeSubtree,
		DerefAliases: ldap.NeverDerefAliases,
		Filter:       filter,
	}

	res, err := z.l.Search(req)
	if err != nil {
		return "", err
	}

	if 1 == len(res.Entries) {
		return res.Entries[0].DN, nil
	}

	if 0 == len(res.Entries) {
		return "", nil
	}

	return "", fmt.Errorf("Too many matching responses.")
}

func (z *Zapper) SeeFull(dn string) (*ldap.Entry, error) {
	return z.getDN(dn, []string{})
}

func (z *Zapper) getDN(dn string, attribs []string) (*ldap.Entry, error) {
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
		Attributes:   attribs,
	}

	res, err := z.l.Search(req)
	if err != nil {
		return nil, err
	}

	if 1 == len(res.Entries) {
		return res.Entries[0], nil
	}

	if 0 == len(res.Entries) {
		return nil, nil
	}

	return nil, fmt.Errorf("Too many matching responses.")
}

func (z *Zapper) Populate(dn string, depth int, obj interface{}) error {
	rv := reflect.ValueOf(obj)
	if rv.Kind() != reflect.Ptr || rv.IsNil() {
		return fmt.Errorf("Invalid object: %s", reflect.TypeOf(obj))
	}
	subKind := reflect.Indirect(rv).Kind()
	if subKind != reflect.Struct {
		return fmt.Errorf("Invalid object: %s", subKind.String())
	}

	// We know we have a pointer to a struct
	rv = reflect.ValueOf(obj).Elem()

	return z.populate(dn, depth, rv)
}

func (z *Zapper) getAttribs(rv reflect.Value) []string {
	baseType := rv.Type().String()

	// Map fields to the strings
	attribs, found := z.attribCache[baseType]
	if !found {
		for i := 0; i < rv.NumField(); i++ {
			tag, specified := rv.Type().Field(i).Tag.Lookup("ldap")
			if specified {
				list := strings.Split(tag, ",")
				if list[0] != "" {
					attribs = append(attribs, list[0])
				}
			}
		}
		z.attribCache[baseType] = attribs
	}

	return attribs
}

func (z *Zapper) getPerson(dn string, rv reflect.Value) (*ldap.Entry, error) {
	baseType := rv.Type().String()
	attribs := z.getAttribs(rv)
	key := ldapCacheKey{objType: baseType, dn: dn}
	var err error
	who, found := z.personCache[key]
	if !found {
		who, err = z.getDN(dn, attribs)
		if err != nil {
			return nil, err
		}
		z.personCache[key] = who
	}

	return who, nil
}

func (z *Zapper) populate(dn string, depth int, rv reflect.Value) error {
	who, err := z.getPerson(dn, rv)

	for i := 0; i < rv.NumField(); i++ {
		field := rv.Field(i)
		ft := field.Type()
		tag, _ := rv.Type().Field(i).Tag.Lookup("ldap")
		if tag != "" {
			for _, a := range who.Attributes {
				if tag == a.Name {
					switch {
					// Normal single string to single string, or truncate list to first found.
					case field.Kind() == reflect.String:
						if 0 < len(a.Values) {
							field.Set(reflect.ValueOf(a.Values[0]))
						}

					// Normal slice of things to a []string
					case field.Kind() == reflect.Slice && ft.Elem().Kind() == reflect.String:
						field.Set(reflect.ValueOf(a.Values))

					// Normal array of things to a [5]string
					case field.Kind() == reflect.Array && ft.Elem().Kind() == reflect.String:
						least := field.Len()
						if len(a.Values) < least {
							least = len(a.Values)
						}
						for j := 0; j < least; j++ {
							field.Index(j).Set(reflect.ValueOf(a.Values[j]))
						}

					// If you have asked for the manager or directReports to be
					// resolved then do that
					case tag == attrManager, tag == attrDirectReports:
						if depth < 0 {
							continue
						}
						nextDepth := -1
						if tag == attrDirectReports {
							nextDepth = depth - 1
						}
						kind := ft.Kind()
						if kind == reflect.Ptr {
							coworker := reflect.New(ft.Elem())
							coworkerDN := a.Values[0]

							err = z.populate(coworkerDN, nextDepth, reflect.ValueOf(coworker.Interface()).Elem())
							if err != nil {
								return err
							}
							field.Set(coworker)
						} else if kind == reflect.Struct {
							coworker := reflect.New(ft)
							coworkerDN := a.Values[0]

							err = z.populate(coworkerDN, nextDepth, reflect.ValueOf(coworker.Interface()).Elem())
							if err != nil {
								return err
							}
							field.Set(coworker.Elem())
						} else if kind == reflect.Array {
							if ft.Elem().Kind() == reflect.Ptr && ft.Elem().Elem().Kind() == reflect.Struct {
								coworker := reflect.New(ft.Elem().Elem())
								coworkerDN := a.Values[0]

								err = z.populate(coworkerDN, nextDepth, reflect.ValueOf(coworker.Interface()).Elem())
								if err != nil {
									return err
								}
								field.Index(0).Set(coworker)
							} else if ft.Elem().Kind() == reflect.Struct {
								least := field.Len()
								if len(a.Values) < least {
									least = len(a.Values)
								}
								for j := 0; j < least; j++ {
									coworkerDN := a.Values[j]

									err = z.populate(coworkerDN, nextDepth, field.Index(j))
									if err != nil {
										return err
									}
								}
							} else {
								panic(fmt.Sprintf("Incompatible type: %s.%s", rv.Type().String(), field.String()))
							}
						} else if kind == reflect.Slice {
							if ft.Elem().Kind() == reflect.Ptr && ft.Elem().Elem().Kind() == reflect.Struct {
								for _, coworkerDN := range a.Values {
									coworker := reflect.New(ft.Elem().Elem())

									err = z.populate(coworkerDN, nextDepth, reflect.ValueOf(coworker.Interface()).Elem())
									if err != nil {
										return err
									}
									field.Set(reflect.Append(field, coworker))
								}
							} else if ft.Elem().Kind() == reflect.Struct {
								for _, coworkerDN := range a.Values {
									coworker := reflect.New(ft.Elem())

									err = z.populate(coworkerDN, nextDepth, reflect.ValueOf(coworker.Interface()).Elem())
									if err != nil {
										return err
									}
									field.Set(reflect.Append(field, coworker.Elem()))
								}
							} else {
								panic(fmt.Sprintf("Incompatible type: %s.%s", rv.Type().String(), field.String()))
							}
						} else {
							panic(fmt.Sprintf("Incompatible type: %s.%s", rv.Type().String(), field.String()))
						}

					default:
						return fmt.Errorf("Not sure what to do with a %s\n", field.Kind())
					}
				}
			}
		}
	}
	return nil
}
