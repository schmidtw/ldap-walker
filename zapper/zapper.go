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
	"strconv"
	"strings"

	"github.com/go-ldap/ldap/v3"
)

const (
	AttrCity                     = "l"
	AttrCommonName               = "cn"
	AttrCompany                  = "company"
	AttrCountry                  = "co"
	AttrCountryCode              = "c"
	AttrDepartment               = "department"
	AttrDescription              = "description"
	AttrDirectReports            = "directReports"
	AttrDisplayName              = "displayName"
	AttrEmail                    = "mail"
	AttrEmployeeID               = "employeeId"
	AttrEmployeeType             = "employeeType"
	AttrGivenName                = "givenName"
	AttrInfo                     = "info"
	AttrInitials                 = "initials"
	AttrIPPhone                  = "ipPhone"
	AttrLastName                 = "sn"
	AttrMailNickname             = "mailNickname"
	AttrManagedObjects           = "managedObjects"
	AttrManager                  = "manager"
	AttrMemberOf                 = "memberOf"
	AttrMobile                   = "mobile"
	AttrMsExchCoManagedObjectsBL = "msExchCoManagedObjectsBL"
	AttrNTID                     = "sAMAccountName"
	AttrObjectCategory           = "objectCategory"
	AttrObjectClass              = "objectClass"
	AttrPager                    = "pager"
	AttrPostalCode               = "postalCode"
	AttrPostOfficeBox            = "postOfficeBox"
	AttrProxyAddresses           = "proxyAddresses"
	AttrSAMAccountName           = "sAMAccountName"
	AttrSAMAccountType           = "sAMAccountType"
	AttrState                    = "st"
	AttrStreetAddress            = "streetAddress"
	AttrTelephoneNumber          = "telephoneNumber"
	AttrThumbnailPhoto           = "thumbnailPhoto"
	AttrTitle                    = "title"
	AttrUserPrincipalName        = "userPrincipalName"
)

type Employee struct {
	City                string              `yaml:"city,omitempty"`
	Name                string              `yaml:"name,omitempty"`
	Company             string              `yaml:"company,omitempty"`
	Country             string              `yaml:"country,omitempty"`
	CountryCode         string              `yaml:"country_code,omitempty"`
	Department          string              `yaml:"department,omitempty"`
	Description         string              `yaml:"description,omitempty"`
	Directs             []*Employee         `yaml:"directs,omitempty"`
	DisplayName         string              `yaml:"display_name,omitempty"`
	Email               string              `yaml:"email,omitempty"`
	EmailAliases        []string            `yaml:"email_aliases,omitempty"`
	EmployeeID          string              `yaml:"employee_id,omitempty"`
	EmployeeType        string              `yaml:"employee_type,omitempty"`
	FirstName           string              `yaml:"first_name,omitempty"`
	Info                string              `yaml:"info,omitempty"`
	Initials            string              `yaml:"initials,omitempty"`
	IPPhone             string              `yaml:"ip_phone,omitempty"`
	LastName            string              `yaml:"last_name,omitempty"`
	Login               string              `yaml:"login,omitempty"`
	ManagedObjects      []string            `yaml:"managed_objects,omitempty"`
	Manager             string              `yaml:"manager,omitempty"`
	MemberOf            []string            `yaml:"member_of,omitempty"`
	Mobile              string              `yaml:"mobile,omitempty"`
	MSECoManagedObjects []string            `yaml:"mse_co_managed_objects,omitempty"`
	NTID                string              `yaml:"ntid,omitempty"`
	ObjectCategory      string              `yaml:"object_category,omitempty"`
	ObjectClass         []string            `yaml:"object_class,omitempty"`
	Pager               string              `yaml:"pager,omitempty"`
	PostalCode          string              `yaml:"postal_code,omitempty"`
	PostOfficeBox       string              `yaml:"post_office_box,omitempty"`
	ProxyAddresses      []string            `yaml:"proxy_addresses,omitempty"`
	SAMAccountName      string              `yaml:"sam_account_name,omitempty"`
	SAMAccountType      string              `yaml:"sam_account_type,omitempty"`
	State               string              `yaml:"state,omitempty"`
	StreetAddress       string              `yaml:"street_address,omitempty"`
	TelephoneNumber     string              `yaml:"telephone_number,omitempty"`
	ThumbnailPhoto      []byte              `yaml:"-"`
	Title               string              `yaml:"title,omitempty"`
	Unknown             map[string][]string `yaml:"unknown_fields"`
}

func (e *Employee) FindByEmail(email string) *Employee {
	if nil == e {
		return nil
	}
	// Normalize to all lowercase once
	return e.findByEmail(strings.ToLower(email))
}

func (e *Employee) findByEmail(email string) *Employee {
	if e.Email == email {
		return e
	}

	for _, alias := range e.EmailAliases {
		if email == alias {
			return e
		}
	}

	for _, directs := range e.Directs {
		found := directs.findByEmail(email)
		if found != nil {
			return found
		}
	}

	return nil
}

func (e *Employee) FindByNTID(ntid string) *Employee {
	if nil == e {
		return nil
	}
	// Normalize to all lowercase once
	return e.findByNTID(strings.ToLower(ntid))
}

func (e *Employee) findByNTID(ntid string) *Employee {
	if e.NTID == ntid {
		return e
	}

	for _, directs := range e.Directs {
		found := directs.findByNTID(ntid)
		if found != nil {
			return found
		}
	}

	return nil
}

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
		Attributes:   z.Attributes,
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
		Attributes:   attribs, //z.Attributes,
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

func getAttrib(s string) string {
	items := strings.Split(s, ",")
	return items[0]
}

func getDepth(s string) (int, error) {
	items := strings.Split(s, ",")
	if len(items) > 1 {
		fmt.Printf("len(items): %d\n", len(items))
		for i := 1; i < len(items); i++ {
			item := items[i]
			fmt.Println(item)
			if strings.HasPrefix(item, "depth") {
				params := strings.Split(item, "=")
				if len(params) == 2 {
					d, err := strconv.Atoi(strings.TrimSpace(params[1]))
					if err != nil {
						return 0, err
					}
					if d < 0 {
						d = -1
					}
				}
				return 0, fmt.Errorf("Invalid depth arguments: '%s'\n", s)
			}
		}
	}

	return -1, nil
}

type ldapCacheKey struct {
	objType string
	dn      string
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

	personCache := make(map[ldapCacheKey]*ldap.Entry)
	attribCache := make(map[string][]string)

	return z.populate(dn, depth, rv, personCache, attribCache)
}

func (z *Zapper) populate(dn string, depth int, rv reflect.Value, personCache map[ldapCacheKey]*ldap.Entry, attribCache map[string][]string) error {
	baseType := rv.Type().String()
	// Map fields to the strings
	attribs, found := attribCache[baseType]
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
	}

	for i := 0; i < rv.NumField(); i++ {
		fmt.Printf("%s .. %s is a %s\n", rv.Type(), rv.Type().Field(i).Name, rv.Type().Field(i).Type.String()) //reflect.TypeOf(obj))
	}

	key := ldapCacheKey{objType: baseType, dn: dn}
	var err error
	who, found := personCache[key]
	if !found {
		who, err = z.getDN(dn, attribs)
		if err != nil {
			return err
		}
		personCache[key] = who
	}

	for i := 0; i < rv.NumField(); i++ {
		field := rv.Field(i)
		//baseType := rv.Type().String()
		tags, _ := rv.Type().Field(i).Tag.Lookup("ldap")
		tag := getAttrib(tags)
		if tag != "" {
			for _, attribute := range who.Attributes {
				if tag == attribute.Name {
					switch {
					// Normal single string to single string, or a mistake & an error
					case field.Kind() == reflect.String && len(attribute.Values) <= 1:
						field.Set(reflect.ValueOf(attribute.Values[0]))
					case field.Kind() == reflect.String && len(attribute.Values) > 1:
						return fmt.Errorf("Too many values were returned for a string: '%s'", tag)

					// Normal array of things to a []string
					case field.Kind() == reflect.Slice && field.Type().Elem().Kind() == reflect.String:
						field.Set(reflect.ValueOf(attribute.Values))

					// If you have asked for the manager to be resolved we'll do that
					case tag == AttrManager, tag == AttrDirectReports:
						if depth < 0 {
							continue
						}
						nextDepth := -1
						if tag == AttrDirectReports {
							nextDepth = depth - 1
						}
						kind := rv.Type().Field(i).Type.Kind()
						fmt.Printf("Kind: %s\n", kind.String())
						if kind == reflect.Ptr {
							mgr := reflect.New(rv.Type().Field(i).Type.Elem())
							mgrDN := attribute.Values[0]

							err = z.populate(mgrDN, nextDepth, reflect.ValueOf(mgr.Interface()).Elem(), personCache, attribCache)
							if err != nil {
								return err
							}
							field.Set(mgr)
						} else if kind == reflect.Struct {
							mgr := reflect.New(rv.Type().Field(i).Type)
							mgrDN := attribute.Values[0]

							err = z.populate(mgrDN, nextDepth, reflect.ValueOf(mgr.Interface()).Elem(), personCache, attribCache)
							if err != nil {
								return err
							}
							field.Set(mgr.Elem())
						} else if kind == reflect.Array {
							if rv.Type().Field(i).Type.Elem().Kind() == reflect.Ptr {
								mgr := reflect.New(rv.Type().Field(i).Type.Elem().Elem())
								mgrDN := attribute.Values[0]

								err = z.populate(mgrDN, nextDepth, reflect.ValueOf(mgr.Interface()).Elem(), personCache, attribCache)
								if err != nil {
									return err
								}
								field.Index(0).Set(mgr)
							} else if rv.Type().Field(i).Type.Elem().Kind() == reflect.Struct {
								least := field.Len()
								if len(attribute.Values) < least {
									least = len(attribute.Values)
								}
								for j := 0; j < least; j++ {
									mgr := reflect.New(rv.Type().Field(i).Type.Elem())
									mgrDN := attribute.Values[j]

									err = z.populate(mgrDN, nextDepth, reflect.ValueOf(mgr.Interface()).Elem(), personCache, attribCache)
									if err != nil {
										return err
									}
									field.Index(j).Set(mgr.Elem())
								}
							} else {
							}
						} else if kind == reflect.Slice {
							if rv.Type().Field(i).Type.Elem().Kind() == reflect.Ptr {
								for _, mgrDN := range attribute.Values {
									mgr := reflect.New(rv.Type().Field(i).Type.Elem().Elem())

									err = z.populate(mgrDN, nextDepth, reflect.ValueOf(mgr.Interface()).Elem(), personCache, attribCache)
									if err != nil {
										return err
									}
									field.Set(reflect.Append(field, mgr))
								}
							} else if rv.Type().Field(i).Type.Elem().Kind() == reflect.Struct {
								for _, mgrDN := range attribute.Values {
									mgr := reflect.New(rv.Type().Field(i).Type.Elem())

									err = z.populate(mgrDN, nextDepth, reflect.ValueOf(mgr.Interface()).Elem(), personCache, attribCache)
									if err != nil {
										return err
									}
									field.Set(reflect.Append(field, mgr.Elem()))
								}
							} else {
							}
						} else {
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

func (z *Zapper) WalkTree(dn string) (*Employee, error) {
	return z.processNode(dn, true)
}

func (z *Zapper) processNode(dn string, directs bool) (*Employee, error) {
	who, err := z.getDN(dn, z.Attributes)
	if err != nil {
		fmt.Printf("Error: %s\n", dn)
		return nil, err
	}

	e := Employee{}
	e.Unknown = make(map[string][]string)

	for _, attribute := range who.Attributes {
		switch attribute.Name {
		case AttrCommonName, "name":
			e.Name = attribute.Values[0]
		case AttrCompany:
			e.Company = attribute.Values[0]
		case AttrCity:
			e.City = attribute.Values[0]
		case AttrCountry:
			e.Country = attribute.Values[0]
		case AttrCountryCode:
			e.CountryCode = attribute.Values[0]
		case AttrDepartment:
			e.Department = attribute.Values[0]
		case AttrDescription:
			e.Description = attribute.Values[0]
		case AttrDirectReports:
			if directs {
				for _, direct := range attribute.Values {
					tmp, err := z.processNode(direct, directs)
					if err != nil {
						fmt.Printf("Error: %s\n", direct)
						return nil, err
					}

					e.Directs = append(e.Directs, tmp)
				}
			}
		case AttrDisplayName:
			e.DisplayName = attribute.Values[0]
		case AttrEmail:
			// Make email addresses all lowercase to help normalize a bit
			e.Email = strings.ToLower(attribute.Values[0])
		case AttrEmployeeID, "employeeID":
			e.EmployeeID = attribute.Values[0]
		case AttrEmployeeType:
			e.EmployeeType = attribute.Values[0]

			switch e.EmployeeType {
			case "E", "Employee", "Emp":
				e.EmployeeType = "employee"
			case "C", "Contractor", "Cont":
				e.EmployeeType = "contractor"
			case "S", "Service User", "service_user":
				e.EmployeeType = "service user"
			case "R", "Reserved User", "Reserved", "reserved":
				e.EmployeeType = "reserved user"
			default:
			}
		case AttrGivenName:
			e.FirstName = attribute.Values[0]
		case AttrInfo:
			e.Info = attribute.Values[0]
		case AttrInitials:
			e.Initials = attribute.Values[0]
		case AttrIPPhone:
			e.IPPhone = attribute.Values[0]
		case AttrLastName:
			e.LastName = attribute.Values[0]
		case AttrMailNickname:
			for _, alias := range attribute.Values {
				e.EmailAliases = append(e.EmailAliases, strings.ToLower(alias))
			}
		case AttrManagedObjects:
			e.ManagedObjects = attribute.Values
		case AttrManager:
			e.Manager = attribute.Values[0]
		case AttrMemberOf:
			e.MemberOf = attribute.Values
		case AttrMobile:
			e.Mobile = attribute.Values[0]
		case AttrMsExchCoManagedObjectsBL:
			e.MSECoManagedObjects = attribute.Values
		case AttrObjectCategory:
			e.ObjectCategory = attribute.Values[0]
		case AttrObjectClass:
			e.ObjectClass = attribute.Values
		case AttrPager:
			e.Pager = attribute.Values[0]
		case AttrPostalCode:
			e.PostalCode = attribute.Values[0]
		case AttrPostOfficeBox:
			e.PostOfficeBox = attribute.Values[0]
		case AttrProxyAddresses:
			e.ProxyAddresses = attribute.Values
		case AttrSAMAccountName:
			// Generally the NTID is case insensitive so make it lowercase
			e.NTID = strings.ToLower(attribute.Values[0])

			// Leave this value to match the original in case it's important
			e.SAMAccountName = attribute.Values[0]
		case AttrSAMAccountType:
			e.SAMAccountType = attribute.Values[0]
		case AttrState:
			e.State = attribute.Values[0]
		case AttrStreetAddress:
			e.StreetAddress = attribute.Values[0]
		case AttrTelephoneNumber:
			e.TelephoneNumber = attribute.Values[0]
		case AttrThumbnailPhoto:
			e.ThumbnailPhoto = attribute.ByteValues[0]
		case AttrTitle:
			e.Title = attribute.Values[0]
		case AttrUserPrincipalName:
			e.Login = attribute.Values[0]

		default:
			/*
				e.Unknown[attribute.Name] = attribute.Values
					for i, _ := range attribute.Values {
						fmt.Printf("'%s' = [%d] '%s'\n", attribute.Name, i, attribute.Values[i])
					}
			*/
		}
	}

	return &e, nil
}
