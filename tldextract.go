package tldextract

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"regexp"
	"strings"
)

//used for Result.Flag
const (
	Malformed = iota
	Domain
	Ip4
	Ip6
)

type Result struct {
	Flag int
	Sub  string
	Root string
	Tld  string
}

type TLDExtract struct {
	CacheFile string
	rootNode  *Trie
	debug     bool
}

type Trie struct {
	ExceptRule bool
	ValidTld   bool
	matches    map[string]*Trie
}

var (
	schemaregex = regexp.MustCompile(`^([abcdefghijklmnopqrstuvwxyz0123456789\+\-\.]+:)?//`)
	ip4regex    = regexp.MustCompile(`(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])`)
)

//New create a new *TLDExtract, it may be shared between goroutines,we usually need a single instance in an application.
func New(cacheFile string, debug bool) (*TLDExtract, error) {
	data, err := ioutil.ReadFile(cacheFile)
	if err != nil {
		data, err = download()
		if err != nil {
			return &TLDExtract{}, err
		}
		ioutil.WriteFile(cacheFile, data, 0644)
	}
	ts := strings.Split(string(data), "\n")
	newMap := make(map[string]*Trie)
	rootNode := &Trie{ExceptRule: false, ValidTld: false, matches: newMap}
	for _, t := range ts {
		if t != "" && !strings.HasPrefix(t, "//") {
			t = strings.TrimSpace(t)
			exceptionRule := t[0] == '!'
			if exceptionRule {
				t = t[1:]
			}
			addTldRule(rootNode, strings.Split(t, "."), exceptionRule)
		}
	}

	return &TLDExtract{CacheFile: cacheFile, rootNode: rootNode, debug: debug}, nil
}

func addTldRule(rootNode *Trie, labels []string, ex bool) {
	numlabs := len(labels)
	t := rootNode
	for i := numlabs - 1; i >= 0; i-- {
		lab := labels[i]
		m, found := t.matches[lab]
		if !found {
			except := ex
			valid := !ex && i == 0
			newMap := make(map[string]*Trie)
			t.matches[lab] = &Trie{ExceptRule: except, ValidTld: valid, matches: newMap}
			m = t.matches[lab]
		}
		t = m
	}
}

func (extract *TLDExtract) Extract(u string) *Result {
	input := u
	u = strings.ToLower(u)
	u = schemaregex.ReplaceAllString(u, "")
	i := strings.Index(u, "@")
	if i != -1 {
		u = u[i+1:]
	}

	index := strings.IndexFunc(u, func(r rune) bool {
		switch r {
		case '&', '/', '?', ':', '#':
			return true
		}
		return false
	})
	if index != -1 {
		u = u[0:index]
	}

	if strings.HasSuffix(u, ".html") {
		u = u[0 : len(u)-len(".html")]
	}
	if extract.debug {
		fmt.Printf("%s;%s\n", u, input)
	}
	return extract.extract(u)
}

func (extract *TLDExtract) extract(url string) *Result {
	domain, tld := extract.extractTld(url)
	if tld == "" {
		ip := net.ParseIP(url)
		if ip != nil {
			if ip4regex.MatchString(url) {
				return &Result{Flag: Ip4, Root: url}
			}
			return &Result{Flag: Ip6, Root: url}
		}
		return &Result{Flag: Malformed}
	}
	sub, root := subdomain(domain)

	for _, c := range root {
		if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || (c == '-') || (c >= 0x80) {
			continue
		}
		return &Result{Flag: Malformed}
	}

	return &Result{Flag: Domain, Root: root, Sub: sub, Tld: tld}
}

func (extract *TLDExtract) extractTld(url string) (domain, tld string) {
	spl := strings.Split(url, ".")
	tldIndex, validTld := extract.getTldIndex(spl)
	if validTld {
		domain = strings.Join(spl[:tldIndex], ".")
		tld = strings.Join(spl[tldIndex:], ".")
	} else {
		domain = url
	}
	return
}

func (extract *TLDExtract) getTldIndex(labels []string) (int, bool) {
	t := extract.rootNode
	parentValid := false
	wildcard := false

	for i := len(labels) - 1; i >= 0; i-- {
		lab := labels[i]

		// If wildcard found before and we reach this point, it means we have an
		// actual domain name besides what the wildcard matches, e.g.
		// *.il in the suffix file and we have a  domain.co.il  instead of only
		// co.il (which would be invalid)
		if wildcard {
			return i + 1, true
		}

		n, exactMatch := t.matches[lab]

		_, wildcard = t.matches["*"]

		switch {
		case exactMatch && !n.ExceptRule:
			parentValid = n.ValidTld // exact match, not exception
			t = n
		case exactMatch: // an exception rule, valid
			return i + 1, true

		case parentValid: // no match and parent was valid tld.
			return i + 1, true

		case wildcard: // on wildcard, continue the loop as we need
			continue // at least another label.

		default: // all other cases
			return -1, false
		}
	}

	return -1, false
}

//return sub domain,root domain
func subdomain(d string) (string, string) {
	ps := strings.Split(d, ".")
	l := len(ps)
	if l == 1 {
		return "", d
	}
	return strings.Join(ps[0:l-1], "."), ps[l-1]
}

func download() ([]byte, error) {
	u := "http://mxr.mozilla.org/mozilla-central/source/netwerk/dns/effective_tld_names.dat?raw=1"
	resp, err := http.Get(u)
	if err != nil {
		return []byte(""), err
	}
	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)

	lines := strings.Split(string(body), "\n")
	var buffer bytes.Buffer

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "//") {
			buffer.WriteString(line)
			buffer.WriteString("\n")
		}
	}

	return buffer.Bytes(), nil
}
