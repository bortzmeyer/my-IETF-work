package dnscache

import (
	"testing"
)

const (
	defaultQtype = 1
)

func Test1rootExists(me *testing.T) {
	ok, result, _ := Get("", defaultQtype)
	if ok.Exists == nil || !*ok.Exists {
		me.Fail()
	}
	if ok.NotAZone == nil || *ok.NotAZone {
		me.Fail()
	}
	if len(result) != 13 {
		me.Fail()
	}
}

func Test2deExists(me *testing.T) {
	ok, result, _ := Get("de", defaultQtype)
	if ok.Exists == nil || !*ok.Exists {
		me.Fail()
	}
	if ok.NotAZone == nil || *ok.NotAZone {
		me.Fail()
	}
	if result[0] != "ns1.denic.de" {
		me.Fail()
	}
}

func Test3heisedeExists(me *testing.T) {
	ok, result, _ := Get("heise.de", defaultQtype)
	if ok.Exists == nil || !*ok.Exists {
		me.Fail()
	}
	if result[1] != "slave.isc.org" {
		me.Fail()
	}
}

func Test4verisigncomExists(me *testing.T) {
	ok, result, _ := Get("www.verisign.com", defaultQtype)
	if ok.Exists == nil || !*ok.Exists {
		me.Fail()
	}
	if len(result) != 0 {
		me.Fail()
	}
	// Test that the final dot is ignored
	ok, result, _ = Get("www.verisign.com.", defaultQtype)
	if ok.Exists == nil || !*ok.Exists {
		me.Fail()
	}
	if len(result) != 0 {
		me.Fail()
	}
}

func Test5comExists(me *testing.T) {
	ok, result, _ := Get("com", defaultQtype)
	if ok.Exists == nil || !*ok.Exists {
		me.Fail()
	}
	// It's not the real .com zone, just the one we created in init()
	if ok.NotAZone != nil {
		me.Fail()
	}
	if ok.Closest != "" {
		me.Fail()
	}
	if len(result) != 0 {
		me.Fail()
	}
}

func Test6verisignExists(me *testing.T) {
	ok, result, _ := Get("verisign.com", defaultQtype)
	if ok.Exists == nil || !*ok.Exists {
		me.Fail()
	}
	if ok.Closest != "verisign.com" {
		me.Fail()
	}
	if result[1] != "ns2" {
		me.Fail()
	}
}

func Test7tldNotExists(me *testing.T) {
	ok, _, _ := Get("foobar.tagada", defaultQtype)
	if ok.Exists == nil || *ok.Exists {
		me.Fail()
	}
	if ok.Closest != "" {
		me.Fail()
	}
}

func Test8domainNotExists(me *testing.T) {
	ok, _, _ := Get("www.acc.google.de", defaultQtype)
	if ok.Exists == nil || *ok.Exists {
		me.Fail()
	}
	if ok.Closest != "de" {
		me.Fail()
	}
}

func Test9unknownTldExists(me *testing.T) {
	ok, _, _ := Get("facebook.de", defaultQtype)
	if ok.Exists != nil {
		me.Fail()
	}
}

func Test10unknownDomainExists(me *testing.T) {
	ok, _, _ := Get("thing.verisign.com", defaultQtype)
	if ok.Exists != nil {
		me.Fail()
	}
	if ok.Closest != "verisign.com" {
		me.Fail()
	}
}

func Test10unknownTldUnknown(me *testing.T) {
	ok, _, _ := Get("www.example.net", defaultQtype)
	if ok.Exists != nil {
		me.Fail()
	}
}

func init() {
	Put("de", []string{"ns1.denic.de"})
	Put("verisign.com", []string{"ns1", "ns2"})
	Put("www.verisign.com", []string{})
	Put("heise.de.", []string{"ns1.1and1.net", "slave.isc.org", "ns.netnod.net"}) // Test that the final dot is ignored
	PutNx("tagada")
	PutNx("google.de")
}
