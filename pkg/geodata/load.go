// Package geodata reads the V2Ray/Xray GeoSiteList and GeoIPList wire formats.
package geodata

import (
	"fmt"
	"net/netip"
	"os"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/IrineSistiana/mosdns/v5/pkg/matcher/domain"
	"google.golang.org/protobuf/encoding/protowire"
)

// ParseGeoSiteRef resolves a GeoSite expression. An empty path and nil error
// indicate an ordinary domain expression.
func ParseGeoSiteRef(rule, defaultPath string) (path, tag string, err error) {
	prefix, ref, ok := strings.Cut(rule, ":")
	if !ok {
		return "", "", nil
	}
	switch prefix {
	case "geosite":
		return defaultFile(defaultPath, "geosite.dat"), ref, nil
	case "ext", "ext-domain", "ext-site":
		return splitExternalRef(ref)
	default:
		return "", "", nil
	}
}

// ParseGeoIPRef resolves a GeoIP expression. An empty path and nil error
// indicate an ordinary IP expression.
func ParseGeoIPRef(rule, defaultPath string) (path, tag string, reverse bool, err error) {
	rule, beforeRule := cutNegation(rule)
	prefix, ref, ok := strings.Cut(rule, ":")
	if !ok {
		return "", "", false, nil
	}
	switch prefix {
	case "geoip":
		path, tag = defaultFile(defaultPath, "geoip.dat"), ref
	case "ext", "ext-ip":
		path, tag, err = splitExternalRef(ref)
		if err != nil {
			return "", "", false, err
		}
	default:
		return "", "", false, nil
	}
	tag, beforeTag := cutNegation(tag)
	return path, tag, beforeRule != beforeTag, nil
}

func defaultFile(path, filename string) string {
	if path == "" {
		return filename
	}
	return path
}

func splitExternalRef(ref string) (path, tag string, err error) {
	// The last colon separates the tag and permits drive letters in paths.
	i := strings.LastIndexByte(ref, ':')
	if i <= 0 || i == len(ref)-1 {
		return "", "", fmt.Errorf("expected file path and tag")
	}
	return ref[:i], ref[i+1:], nil
}

func cutNegation(rule string) (string, bool) {
	rest := strings.TrimLeft(rule, "!")
	return rest, (len(rule)-len(rest))%2 != 0
}

// LoadGeoSite adds domain rules from one tag, optionally filtered by @attributes.
func LoadGeoSite(path, ref string, matcher *domain.MixMatcher[struct{}]) error {
	tag, attrs, hasAttrs := strings.Cut(ref, "@")
	var wanted []string
	if hasAttrs {
		wanted = strings.Split(attrs, "@")
		for _, attr := range wanted {
			if attr == "" {
				return fmt.Errorf("empty geosite attribute in %q", ref)
			}
		}
	}
	return loadGroup(path, tag, "geosite", func(rule []byte) error {
		var typ uint64
		var value string
		var attrs []string
		fields := message{data: rule}
		for fields.next() {
			switch {
			case fields.is(1, protowire.VarintType):
				typ = fields.uint()
			case fields.is(2, protowire.BytesType):
				value = string(fields.bytes())
			case len(wanted) > 0 && fields.is(3, protowire.BytesType):
				key, err := readName(fields.bytes())
				if err != nil {
					return err
				}
				attrs = append(attrs, key)
			}
		}
		if fields.err != nil {
			return fields.err
		}
		for _, attr := range wanted {
			if !slices.ContainsFunc(attrs, func(key string) bool { return strings.EqualFold(key, attr) }) {
				return nil
			}
		}
		types := [...]string{domain.MatcherKeyword, domain.MatcherRegexp, domain.MatcherDomain, domain.MatcherFull}
		if typ >= uint64(len(types)) || value == "" || !utf8.ValidString(value) {
			return fmt.Errorf("invalid geosite domain type %d or value %q", typ, value)
		}
		return matcher.GetSubMatcher(types[typ]).Add(value, struct{}{})
	})
}

// LoadGeoIP adds the IPv4 and IPv6 prefixes from one tag.
func LoadGeoIP(path, tag string, add func(netip.Prefix)) error {
	return loadGroup(path, tag, "geoip", func(rule []byte) error {
		var ip []byte
		var bits uint64
		fields := message{data: rule}
		for fields.next() {
			switch {
			case fields.is(1, protowire.BytesType):
				ip = fields.bytes()
			case fields.is(2, protowire.VarintType):
				bits = fields.uint()
			}
		}
		if fields.err != nil {
			return fields.err
		}
		addr, ok := netip.AddrFromSlice(ip)
		if !ok || bits > uint64(addr.BitLen()) {
			return fmt.Errorf("invalid geoip CIDR %v/%d", ip, bits)
		}
		add(netip.PrefixFrom(addr, int(bits)))
		return nil
	})
}

// Both List messages contain groups in field 1. A group has its tag in
// field 1 and its repeated rules in field 2.
func loadGroup(path, tag, kind string, add func([]byte) error) error {
	if tag == "" {
		return fmt.Errorf("empty %s tag", kind)
	}
	if path == "" {
		return fmt.Errorf("geodata.%s file path is required", kind)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	err = decodeGroup(data, tag, add)
	if err != nil {
		return fmt.Errorf("%s file %q tag %q: %w", kind, path, tag, err)
	}
	return nil
}

func decodeGroup(data []byte, tag string, add func([]byte) error) error {
	list := message{data: data}
	for list.next() {
		if !list.is(1, protowire.BytesType) {
			continue
		}
		entry := list.bytes()
		name, err := readName(entry)
		if err != nil {
			return err
		}
		if !strings.EqualFold(tag, name) {
			continue
		}
		group := message{data: entry}
		for group.next() {
			if group.is(2, protowire.BytesType) {
				if err := add(group.bytes()); err != nil {
					return err
				}
			}
		}
		return group.err
	}
	if list.err != nil {
		return list.err
	}
	return fmt.Errorf("tag not found")
}

func readName(data []byte) (string, error) {
	fields := message{data: data}
	var name string
	for fields.next() {
		if fields.is(1, protowire.BytesType) {
			name = string(fields.bytes())
		}
	}
	return name, fields.err
}

type message struct {
	data   []byte
	number protowire.Number
	kind   protowire.Type
	value  []byte
	err    error
}

func (m *message) next() bool {
	if len(m.data) == 0 {
		return false
	}
	number, kind, tagLen := protowire.ConsumeTag(m.data)
	if tagLen < 0 {
		m.err = protowire.ParseError(tagLen)
		return false
	}
	data := m.data[tagLen:]
	valueLen := protowire.ConsumeFieldValue(number, kind, data)
	if valueLen < 0 {
		m.err = protowire.ParseError(valueLen)
		return false
	}
	m.number, m.kind, m.value = number, kind, data[:valueLen]
	m.data = data[valueLen:]
	return true
}

func (m *message) is(number protowire.Number, kind protowire.Type) bool {
	return m.number == number && m.kind == kind
}

func (m *message) bytes() []byte {
	value, _ := protowire.ConsumeBytes(m.value)
	return value
}

func (m *message) uint() uint64 {
	value, _ := protowire.ConsumeVarint(m.value)
	return value
}
