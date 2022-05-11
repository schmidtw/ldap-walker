/*
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

// Package zapper is a helper library that lightly wraps go-ldap with the
// ability to populate a provided structure with tags from the desired ldap
// service.
package zapper

import (
	"crypto/tls"
	"errors"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
)

const (
	attrDirectReports = "directReports"
	attrManager       = "manager"
)

var (
	// ErrUnknownType means the code is unsure what to do with this type.
	ErrUnknownType = errors.New("unable to handle type")

	// ErrTooManyResponses means the code expected 1 and got many.
	ErrTooManyResponses = errors.New("too many matching responses")

	// ErrInvalidType means the type of something provided isn't valid.
	ErrInvalidType = errors.New("invalid object")
)

// Zapper contains the configuration input that define how to talk to
// the ldap server of interest.
type Zapper struct {
	BaseDN      string      // The base DN to search with.  Example: 'DC=example,dc=com'
	User        string      // Username to log in with.
	Password    string      // Password to log in with.
	Hostname    string      // Hostname url. Example: 'ldap.example.com'
	Port        int         // Port to use. Typically: 3269
	TLSConfig   *tls.Config // Provide any special TLS needs for your server here.
	l           *ldap.Conn
	ldapCache   map[cacheKey]*ldap.Entry
	objCache    map[cacheKey]interface{}
	attribCache map[string][]string
}

type cacheKey struct {
	objType string
	dn      string
}

// NewZapper takes an existing go-ldap object and base DN and creates a working
// Zapper object.  This allows full control of the connection.
func NewZapper(BaseDN string, l *ldap.Conn) *Zapper {
	z := &Zapper{
		BaseDN: BaseDN,
		l:      l,
	}

	return z
}

// Connect is a helper that connects/binds to the ldap server in a normal way
// using the specified username & password.
func (z *Zapper) Connect() error {
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
	z.ldapCache = make(map[cacheKey]*ldap.Entry)
	z.objCache = make(map[cacheKey]interface{})
	z.attribCache = make(map[string][]string)

	return nil
}

// Close closes the connection to the ldap server.
func (z *Zapper) Close() {
	if z.l != nil {
		z.l.Close()
	}
}

// FindByNTID looks through the ldap service for the matching NTID.  NTID is
// called sAMAccountName in ldap terminology.
func (z *Zapper) FindByNTID(ntid string) (string, error) {
	return z.Find(fmt.Sprintf("(&(objectClass=user)(sAMAccountName=%s))", ldap.EscapeFilter(ntid)))
}

// FindByEmail looks through the ldap service for the matching email address.
// Note that this doesn't search all possible places an email can be present,
// just the designated 'mail' location.
func (z *Zapper) FindByEmail(email string) (string, error) {
	return z.Find(fmt.Sprintf("(&(objectClass=user)(mail=%s))", ldap.EscapeFilter(email)))
}

// Find provides a simple wrapper that allows the caller to specify their own
// query filter.  Make sure to ldap.EscapeFilter() any input to prevent encoding
// errors from being returned.
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

	return "", ErrTooManyResponses
}

// SeeFull provides a simple way to get everything known about a specific
// distingushed name.  This is often helpful in determining what data your
// ldap service has available.
func (z *Zapper) SeeFull(dn string) (*ldap.Entry, error) {
	return z.getDN(dn, []string{})
}

// getDN is a simple helper that gets exactly one dn Entry or fails.
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

	return nil, ErrTooManyResponses
}

// Populate starts with the distinguished name and walks the tree down from
// that point the number of levels specified by the depth.  The output is stored
// in the interface provided based on `ldap:"field"` tags and the field type.
// The obj field must be a struct or a pointer to a struct.
//
// Examples of struct field tags and their meanings:
//
//   // Field of type int means the resulting data from ldap entity 'groupId'
//	 // must be a number that can be converted to an int.
//   Field int `ldap:"groupId"`
//
//   // Field of type string means the resulting data from ldap entity 'name'
//	 // is exactly one string.
//   Field string `ldap:"name"`
//
//   // Field of type []string means the resulting data from ldap entity 'name'
//	 // is a list of strings and keep all of them.
//   Field []string `ldap:"name"`
//
//   // Field of type [5]string means the resulting data from ldap entity 'name'
//	 // is a list of strings and keep up to 5.
//   Field [5]string `ldap:"name"`
//
//   // Field of type time.Time means the resulting data from ldap entity 'hireDate'
//	 // is a date of format '060102150405Z' (See time.Time for details).
//   Field time.Time `ldap:"hireDate,060102150405Z"`
//
//	 // In this example, the Foo structure will be created as a tree based on
//   // the 'directReports' and 'manager' returned by ldap.  The pointers allow
//   // the structures to refer back up the same tree so pointer navigation is
//   // possible.
//	 type Foo struct {
//	     Directs []*Foo		`ldap:"directReports"`
//		 Manager *Foo		`ldap:"manager"`
//	 }
//
//	 // This example shows that types need not be consistent.  And that limits
//   // the maximum directs reported back to 3.  Note that the order is not
//   // assured, so it could be a different subset each time.
//   type Bar struct {
//       Name string `ldap:"name"`
//   }
//
//   type Other struct {
//       Id string `ldap:"groupId"`
//   }
//
//	 type Foo struct {
//	     Directs [3]Bar		`ldap:"directReports"`
//		 Manager Other		`ldap:"manager"`
//	 }
func (z *Zapper) Populate(dn string, depth int, obj interface{}) error {
	rv := reflect.ValueOf(obj)
	if rv.Kind() != reflect.Ptr || rv.IsNil() {
		return fmt.Errorf("%v, invalid obj", ErrInvalidType)
	}
	subKind := reflect.Indirect(rv).Kind()
	if subKind != reflect.Struct {
		return fmt.Errorf("%v, invalid obj", ErrInvalidType)
	}

	return z.populate(dn, depth, rv)
}

// A helper function
func (z *Zapper) getAttribs(rv reflect.Value) []string {
	baseType := rv.Type().String()

	// Map fields to the strings
	attribs, found := z.attribCache[baseType]
	if !found {
		for i := 0; i < rv.NumField(); i++ {
			all, specified := rv.Type().Field(i).Tag.Lookup("ldap")
			tags := strings.Split(all, ",")
			if specified {
				list := strings.Split(tags[0], ",")
				if list[0] != "" {
					attribs = append(attribs, list[0])
				}
			}
		}
		z.attribCache[baseType] = attribs
	}

	return attribs
}

func (z *Zapper) getLdap(dn string, rv reflect.Value) (*ldap.Entry, error) {
	baseType := rv.Type().String()
	attribs := z.getAttribs(rv)
	key := cacheKey{objType: baseType, dn: dn}
	var err error
	who, found := z.ldapCache[key]
	if !found {
		who, err = z.getDN(dn, attribs)
		if err != nil {
			return nil, err
		}
		z.ldapCache[key] = who
	}

	return who, nil
}

func getType(in string, t reflect.Type) (string, error) {
	k := t.Kind()
	switch k {
	case reflect.Array:
		return getType(fmt.Sprintf("%s|array", in), t.Elem())
	case reflect.Ptr:
		return getType(fmt.Sprintf("%s|ptr", in), t.Elem())
	case reflect.Slice:
		return getType(fmt.Sprintf("%s|slice", in), t.Elem())
	case reflect.Struct:
		return fmt.Sprintf("%s|struct|%s|%s", in, t.PkgPath(), t.Name()), nil

	default:
		return fmt.Sprintf("%s|%s", in, k.String()), nil
	}

	return "", ErrUnknownType
}

func (z *Zapper) populate(dn string, depth int, rv reflect.Value) error {
	t, err := getType("", rv.Type())
	if err != nil {
		return err
	}
	key := cacheKey{objType: t, dn: dn}
	if _, found := z.objCache[key]; !found {
		z.objCache[key] = rv.Interface()
	}
	rv = rv.Elem()
	who, err := z.getLdap(dn, rv)

	for i := 0; i < rv.NumField(); i++ {
		field := rv.Field(i)
		ft := field.Type()
		all, _ := rv.Type().Field(i).Tag.Lookup("ldap")
		tags := strings.Split(all, ",")
		tag := tags[0]
		if tag != "" {
			for _, a := range who.Attributes {
				if tag == a.Name {
					switch {
					// Normal single string to single string, or truncate list to first found.
					case field.Kind() == reflect.String:
						if 0 < len(a.Values) {
							field.Set(reflect.ValueOf(a.Values[0]))
						}

					case field.Kind() == reflect.Int:
						if 0 < len(a.Values) {
							i, err := strconv.Atoi(a.Values[0])
							if err != nil {
								return err
							}
							field.Set(reflect.ValueOf(i))
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

					case field.Kind() == reflect.Struct &&
						field.Type().PkgPath() == "time" &&
						field.Type().Name() == "Time" &&
						len(tags) > 1:

						if len(a.Values) > 0 {
							t, err := time.Parse(tags[1], a.Values[0])
							if err != nil {
								return err
							}
							field.Set(reflect.ValueOf(t))
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
						if kind == reflect.Ptr && ft.Elem().Kind() == reflect.Struct {
							coworkerDN := a.Values[0]
							subType, err := getType("", ft)
							if err != nil {
								return err
							}
							key := cacheKey{objType: subType, dn: coworkerDN}
							if coworker, found := z.objCache[key]; found {
								field.Set(reflect.ValueOf(coworker))
							} else {
								coworker := reflect.New(ft.Elem())

								err = z.populate(coworkerDN, nextDepth, reflect.ValueOf(coworker.Interface()))
								if err != nil {
									return err
								}
								z.objCache[key] = coworker
								field.Set(coworker)
							}
						} else if kind == reflect.Struct {
							coworker := reflect.New(ft)
							coworkerDN := a.Values[0]

							err = z.populate(coworkerDN, nextDepth, reflect.ValueOf(coworker.Interface()))
							if err != nil {
								return err
							}
							field.Set(coworker.Elem())
						} else if kind == reflect.Array {
							if ft.Elem().Kind() == reflect.Ptr && ft.Elem().Elem().Kind() == reflect.Struct {
								coworker := reflect.New(ft.Elem().Elem())
								coworkerDN := a.Values[0]

								err = z.populate(coworkerDN, nextDepth, reflect.ValueOf(coworker.Interface()))
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
								return fmt.Errorf("%v, field type: %s.%s", ErrInvalidType, rv.Type().String(), field.String())
							}
						} else if kind == reflect.Slice {
							// if *struct
							if ft.Elem().Kind() == reflect.Ptr && ft.Elem().Elem().Kind() == reflect.Struct {
								subType, err := getType("", ft)
								for _, coworkerDN := range a.Values {
									if err != nil {
										return err
									}
									key := cacheKey{objType: subType, dn: coworkerDN}
									coworker, found := z.objCache[key]
									if !found {
										coworker = reflect.New(ft.Elem().Elem())

										//err = z.populate(coworkerDN, nextDepth, coworker.(reflect.Value))
										err = z.populate(coworkerDN, nextDepth, reflect.ValueOf(coworker.(reflect.Value).Interface()))
										if err != nil {
											return err
										}
										z.objCache[key] = coworker
									}
									field.Set(reflect.Append(field, reflect.ValueOf(coworker.(reflect.Value).Interface())))
								}
							} else if ft.Elem().Kind() == reflect.Struct {
								for _, coworkerDN := range a.Values {
									coworker := reflect.New(ft.Elem())

									err = z.populate(coworkerDN, nextDepth, reflect.ValueOf(coworker.Interface()))
									if err != nil {
										return err
									}
									field.Set(reflect.Append(field, coworker.Elem()))
								}
							} else {
								return fmt.Errorf("%v, field type: %s.%s", ErrInvalidType, rv.Type().String(), field.String())
							}
						} else {
							return fmt.Errorf("%v, field type: %s.%s", ErrInvalidType, rv.Type().String(), field.String())
						}

					default:
						return fmt.Errorf("%v, field type: %s", ErrInvalidType, field.Kind())
					}
				}
			}
		}
	}
	return nil
}
