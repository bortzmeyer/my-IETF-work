/* This package implements a cache for domain names

Stephane Bortzmeyer <bortzmeyer@nic.fr> */

package dnscache

import (
	// Standard packages
	"strings"
	// External packages
	"github.com/miekg/dns"
)

type tree struct {
	label       string
	fqdn        string
	exists      bool
	nameservers *[]string // If nil, we don't know. If nil and the array is empty, it means there is no zone cut,
	// you find the name servers in a parent.
	data     map[uint16][]dns.RR
	children map[string]tree
}

type Reply struct {
	Exists   *bool  // nil if we don't know
	NotAZone *bool  // nil if we don't know
	Closest  string // No meaning if it is a zone. Otherwise, indicating the closest _known_ parent zone
}

var (
	root tree
	// So we can take their addresses
	True  bool = true
	False bool = false
)

func (t *tree) put(name string, fqdn string, nx bool, ns []string) {
	if name[len(name)-1] == '.' {
		name = name[0 : len(name)-1]
	}
	labels := strings.Split(name, ".")
	upperDomain := labels[len(labels)-1]
	_, ok := t.children[upperDomain]
	newFqdn := ""
	if !ok {
		if t.fqdn == "" {
			newFqdn = upperDomain
		} else {
			newFqdn = upperDomain + "." + t.fqdn
		}
		t.children[upperDomain] = tree{label: upperDomain, fqdn: newFqdn, exists: true,
			nameservers: nil, children: map[string]tree{}}
	}
	if len(labels) == 1 {
		// Famous issue 3117 http://stackoverflow.com/a/24221658/15625
		// https://code.google.com/p/go/issues/detail?id=3117
		tmp := t.children[upperDomain]
		tmp.nameservers = &ns
		tmp.exists = !nx
		t.children[upperDomain] = tmp
	} else {
		sname := strings.Join(labels[0:len(labels)-1], ".")
		up := t.children[upperDomain]
		up.put(sname, fqdn, nx, ns)
	}
}

func Put(name string, ns []string) {
	if name == "" {
		panic("Empty string: cannot Put the root")
	}
	root.put(strings.ToLower(name), strings.ToLower(name), false, ns)
}

func PutNx(name string) {
	if name == "" {
		panic("Empty string: cannot Put the root")
	}
	root.put(strings.ToLower(name), strings.ToLower(name), true, []string{})
}

func (t *tree) get(name string, qtype uint16, closest string) (reply Reply, nameservers []string, records []dns.RR) {
	if name[len(name)-1] == '.' {
		name = name[0 : len(name)-1]
	}
	labels := strings.Split(name, ".")
	upperDomain := labels[len(labels)-1]
	closestParent := closest
	if t.nameservers != nil && len(*t.nameservers) > 0 {
		closestParent = t.fqdn
	}
	child, ok := t.children[upperDomain]
	if !ok {
		return Reply{Exists: nil, NotAZone: nil, Closest: closestParent}, nil, nil
	} else {
		if !child.exists { /* Note this is a reasonable
			   /* behaviour, since DNS is hierarchical but
			   /* this is not how most resolvers work,
			   /* since it breaks with stupid nameservers
			   /* (such as Akamai's who return NXDOMAIN
			   /* for ENTs - Empty Non-terminals. See
			   /* Internet-Draft
			   /* draft-vixie-dnsext-resimprove, section
			   /* 3*/
			return Reply{Exists: &False, NotAZone: nil, Closest: closestParent}, nil, nil
		} else {
			if len(labels) == 1 {
				if child.nameservers == nil {
					return Reply{Exists: &True, NotAZone: nil, Closest: closestParent}, []string{}, nil
				} else {
					notazone := len(*child.nameservers) == 0
					if !notazone {
						closestParent = child.fqdn
					}
					return Reply{Exists: &True, NotAZone: &notazone, Closest: closestParent}, *child.nameservers, nil
				}
			} else {
				sname := strings.Join(labels[0:len(labels)-1], ".")
				return child.get(sname, qtype, closestParent)
			}
		}
	}
}

func Get(name string, qtype uint16) (reply Reply, nameservers []string, records []dns.RR) {
	if name == "" { // The root is special
		return Reply{Exists: &True, NotAZone: &False, Closest: ""}, *root.nameservers, nil
	}
	return root.get(strings.ToLower(name), qtype, "")
}

func init() {
	root = tree{label: "", fqdn: "", exists: true,
		nameservers: &[]string{"a.root-servers.net", "b.root-servers.net", "c.root-servers.net",
			"d.root-servers.net", "e.root-servers.net", "f.root-servers.net",
			"g.root-servers.net", "h.root-servers.net", "i.root-servers.net",
			"j.root-servers.net", "k.root-servers.net", "l.root-servers.net",
			"m.root-servers.net"}, children: map[string]tree{}}
}
