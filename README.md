# ldap-walker
A simple ldap to yaml walker written in go

[![Go Reference](https://pkg.go.dev/badge/github.com/schmidtw/ldap-walker.svg)](https://pkg.go.dev/github.com/schmidtw/ldap-walker)

Usage:

```
ldap-walker <user> [output.yaml]
```

User is required, but the output file is optional.  If omitted the yaml file is
output to stdout.
