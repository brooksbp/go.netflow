package nfv9

import (
	"bytes"
	"encoding/binary"
	"strconv"

	"github.com/brooksbp/go.netflow/pkg/net2"
)

type FieldTypeEntry struct {
	Name        string
	Length      int
	String      func(bytes []uint8) string
	Description string
}

var FieldMap = map[int]FieldTypeEntry{
	1:   FieldTypeEntry{"IN_BYTES", -1, StringDefault, "Incoming counter with length N x 8 bits for number of bytes associated with an IP Flow"},
	2:   FieldTypeEntry{"IN_PKTS", -1, StringDefault, "Incoming counter with length N x 8 bits for the number of packets associated with an IP Flow"},
	3:   FieldTypeEntry{"FLOWS", -1, StringDefault, "Number of flows that were aggregated; default for N is 4"},
	4:   FieldTypeEntry{"PROTOCOL", 1, StringIPProtocol, "IP protocol byte"},
	5:   FieldTypeEntry{"SRC_TOS", 1, StringDefault, "Type of Service byte setting when entering incoming interface"},
	6:   FieldTypeEntry{"TCP_FLAGS", 1, StringDefault, "Cumulative of all the TCP flags seen for this flow"},
	7:   FieldTypeEntry{"L4_SRC_PORT", 2, StringDefault, "TCP/UDP source port number i.e.: FTP, Telnet, or equivalent"},
	8:   FieldTypeEntry{"IPV4_SRC_ADDR", 4, StringIPv4, "IPv4 source address"},
	9:   FieldTypeEntry{"SRC_MASK", 1, StringDefault, "The number of contiguous bits in the source address subnet mask i.e.: the submask in slash notation"},
	10:  FieldTypeEntry{"INPUT_SNMP", -1, StringDefault, "Input interface index; default for N is 2 but higher values could be used"},
	11:  FieldTypeEntry{"L4_DST_PORT", 2, StringDefault, "TCP/UDP destination port number i.e.: FTP, Telnet, or equivalent"},
	12:  FieldTypeEntry{"IPV4_DST_ADDR", 4, StringIPv4, "IPv4 destination address"},
	13:  FieldTypeEntry{"DST_MASK", 1, StringDefault, "The number of contiguous bits in the destination address subnet mask i.e.: the submask in slash notation"},
	14:  FieldTypeEntry{"OUTPUT_SNMP", -1, StringDefault, "Output interface index; default for N is 2 but higher values could be used"},
	15:  FieldTypeEntry{"IPV4_NEXT_HOP", 4, StringIPv4, "IPv4 address of next-hop router"},
	16:  FieldTypeEntry{"SRC_AS", -1, StringDefault, "Source BGP autonomous system number where N could be 2 or 4"},
	17:  FieldTypeEntry{"DST_AS", -1, StringDefault, "Destination BGP autonomous system number where N could be 2 or 4"},
	18:  FieldTypeEntry{"BGP_IPV4_NEXT_HOP", 4, StringDefault, "Next-hop router's IP in the BGP domain'"},
	19:  FieldTypeEntry{"MUL_DST_PKTS", -1, StringDefault, ""},
	20:  FieldTypeEntry{"MUL_DST_BYTES", -1, StringDefault, ""},
	21:  FieldTypeEntry{"LAST_SWITCHED", -1, StringDefault, ""},
	22:  FieldTypeEntry{"FIRST_SWITCHED", -1, StringDefault, ""},
	23:  FieldTypeEntry{"OUT_BYTES", -1, StringDefault, ""},
	24:  FieldTypeEntry{"OUT_PKTS", -1, StringDefault, ""},
	25:  FieldTypeEntry{"MIN_PKT_LNGTH", -1, StringDefault, ""},
	26:  FieldTypeEntry{"MAX_PKT_LNGTH", -1, StringDefault, ""},
	27:  FieldTypeEntry{"IPV6_SRC_ADDR", -1, StringDefault, ""},
	28:  FieldTypeEntry{"IPV6_DST_ADDR", -1, StringDefault, ""},
	29:  FieldTypeEntry{"IPV6_SRC_MASK", -1, StringDefault, ""},
	30:  FieldTypeEntry{"IPV6_DST_MASK", -1, StringDefault, ""},
	31:  FieldTypeEntry{"IPV6_FLOW_LABEL", -1, StringDefault, ""},
	32:  FieldTypeEntry{"ICMP_TYPE", -1, StringDefault, ""},
	33:  FieldTypeEntry{"MUL_IGMP_TYPE", -1, StringDefault, ""},
	34:  FieldTypeEntry{"SAMPLING_INTERVAL", -1, StringDefault, ""},
	35:  FieldTypeEntry{"SAMPLING_ALGORITHM", -1, StringDefault, ""},
	36:  FieldTypeEntry{"FLOW_ACTIVE_TIMEOUT", -1, StringDefault, ""},
	37:  FieldTypeEntry{"FLOW_INACTIVE_TIMEOUT", -1, StringDefault, ""},
	38:  FieldTypeEntry{"ENGINE_TYPE", -1, StringDefault, ""},
	39:  FieldTypeEntry{"ENGINE_ID", -1, StringDefault, ""},
	40:  FieldTypeEntry{"TOTAL_BYTES_EXP", -1, StringDefault, ""},
	41:  FieldTypeEntry{"TOTAL_PKTS_EXP", -1, StringDefault, ""},
	42:  FieldTypeEntry{"TOTAL_FLOWS_EXP", -1, StringDefault, ""},
	43:  FieldTypeEntry{"*Vendor Proprietary*", -1, StringDefault, ""},
	44:  FieldTypeEntry{"IPV4_SRC_PREFIX", -1, StringDefault, ""},
	45:  FieldTypeEntry{"IPV4_DST_PREFIX", -1, StringDefault, ""},
	46:  FieldTypeEntry{"MPLS_TOP_LABEL_TYPE", -1, StringDefault, ""},
	47:  FieldTypeEntry{"MPLS_TOP_LABEL_IP_ADDR", -1, StringDefault, ""},
	48:  FieldTypeEntry{"FLOW_SAMPLER_ID", -1, StringDefault, ""},
	49:  FieldTypeEntry{"FLOW_SAMPLER_MODE", -1, StringDefault, ""},
	50:  FieldTypeEntry{"FLOW_SAMPLER_RANDOM_INTERVAL", -1, StringDefault, ""},
	51:  FieldTypeEntry{"*Vendor Proprietary*", -1, StringDefault, ""},
	52:  FieldTypeEntry{"MIN_TTL", -1, StringDefault, ""},
	53:  FieldTypeEntry{"MAX_TTL", -1, StringDefault, ""},
	54:  FieldTypeEntry{"IPV4_IDENT", -1, StringDefault, ""},
	55:  FieldTypeEntry{"DST_TOS", -1, StringDefault, ""},
	56:  FieldTypeEntry{"IN_SRC_MAC", -1, StringMAC, ""},
	57:  FieldTypeEntry{"OUT_DST_MAC", -1, StringMAC, ""},
	58:  FieldTypeEntry{"SRC_VLAN", -1, StringDefault, ""},
	59:  FieldTypeEntry{"DST_VLAN", -1, StringDefault, ""},
	60:  FieldTypeEntry{"IP_PROTOCOL_VERSION", -1, StringDefault, ""},
	61:  FieldTypeEntry{"DIRECTION", -1, StringDefault, ""},
	62:  FieldTypeEntry{"IPV6_NEXT_HOP", -1, StringDefault, ""},
	63:  FieldTypeEntry{"BGP_IPV6_NEXT_HOP", -1, StringDefault, ""},
	64:  FieldTypeEntry{"IPV6_OPTIONS_HEADERS", -1, StringDefault, ""},
	65:  FieldTypeEntry{"*Vendor Proprietary*", -1, StringDefault, ""},
	66:  FieldTypeEntry{"*Vendor Proprietary*", -1, StringDefault, ""},
	67:  FieldTypeEntry{"*Vendor Proprietary*", -1, StringDefault, ""},
	68:  FieldTypeEntry{"*Vendor Proprietary*", -1, StringDefault, ""},
	69:  FieldTypeEntry{"*Vendor Proprietary*", -1, StringDefault, ""},
	70:  FieldTypeEntry{"MPLS_LABEL_1", -1, StringDefault, ""},
	71:  FieldTypeEntry{"MPLS_LABEL_2", -1, StringDefault, ""},
	72:  FieldTypeEntry{"MPLS_LABEL_3", -1, StringDefault, ""},
	73:  FieldTypeEntry{"MPLS_LABEL_4", -1, StringDefault, ""},
	74:  FieldTypeEntry{"MPLS_LABEL_5", -1, StringDefault, ""},
	75:  FieldTypeEntry{"MPLS_LABEL_6", -1, StringDefault, ""},
	76:  FieldTypeEntry{"MPLS_LABEL_7", -1, StringDefault, ""},
	77:  FieldTypeEntry{"MPLS_LABEL_8", -1, StringDefault, ""},
	78:  FieldTypeEntry{"MPLS_LABEL_9", -1, StringDefault, ""},
	79:  FieldTypeEntry{"MPLS_LABEL_10", -1, StringDefault, ""},
	80:  FieldTypeEntry{"IN_DST_MAC", -1, StringMAC, ""},
	81:  FieldTypeEntry{"OUT_SRC_MAC", -1, StringMAC, ""},
	82:  FieldTypeEntry{"IF_NAME", -1, StringDefault, ""},
	83:  FieldTypeEntry{"IF_DESC", -1, StringDefault, ""},
	84:  FieldTypeEntry{"SAMPLER_NAME", -1, StringDefault, ""},
	85:  FieldTypeEntry{"IN_PERMANENT_BYTES", -1, StringDefault, ""},
	86:  FieldTypeEntry{"IN_PERMANENT_PKTS", -1, StringDefault, ""},
	87:  FieldTypeEntry{"*Vendor Proprietary", -1, StringDefault, ""},
	88:  FieldTypeEntry{"FRAGMENT_OFFSET", -1, StringDefault, ""},
	89:  FieldTypeEntry{"FORWARDING_STATUS", -1, StringDefault, ""},
	90:  FieldTypeEntry{"MPLS_PAL_RD", -1, StringDefault, ""},
	91:  FieldTypeEntry{"MPLS_PREFIX_LEN", -1, StringDefault, ""},
	92:  FieldTypeEntry{"SRC_TRAFFIC_INDEX", -1, StringDefault, ""},
	93:  FieldTypeEntry{"DST_TRAFFIC_INDEX", -1, StringDefault, ""},
	94:  FieldTypeEntry{"APPLICATION_DESCRIPTION", -1, StringDefault, ""},
	95:  FieldTypeEntry{"APPLICATION_TAG", -1, StringDefault, ""},
	96:  FieldTypeEntry{"APPLICATION_NAME", -1, StringDefault, ""},
	97:  FieldTypeEntry{"postipDiffServCodePoint", -1, StringDefault, ""},
	98:  FieldTypeEntry{"replication factor", -1, StringDefault, ""},
	99:  FieldTypeEntry{"DEPRECATED", -1, StringDefault, ""},
	100: FieldTypeEntry{"layer2packetSectionOffset", -1, StringDefault, ""},
	101: FieldTypeEntry{"layer2packetSectionSize", -1, StringDefault, ""},
	102: FieldTypeEntry{"layer2packetSectionData", -1, StringDefault, ""},
	298: FieldTypeEntry{"initiatorPackets", 8, StringDefault, ""},
	299: FieldTypeEntry{"responderPackets", 8, StringDefault, ""},
	231: FieldTypeEntry{"initiatorOctets", 8, StringDefault, ""},
	232: FieldTypeEntry{"responderOctets", 8, StringDefault, ""},
}

func StringDefault(b []uint8) string {
	switch len(b) {
	case 1:
		return strconv.Itoa(int(b[0]))
	case 2:
		var n uint16
		binary.Read(bytes.NewBuffer(b), binary.BigEndian, &n)
		return strconv.Itoa(int(n))
	case 4:
		var n uint32
		binary.Read(bytes.NewBuffer(b), binary.BigEndian, &n)
		return strconv.Itoa(int(n))
	case 8:
		var n uint64
		binary.Read(bytes.NewBuffer(b), binary.BigEndian, &n)
		return strconv.Itoa(int(n))
	}

	// Fall back to generic approach.
	s := ""
	for _, n := range b {
		s += strconv.Itoa(int(n)) + " "
	}
	return s
}

func StringIPv4(bytes []uint8) string {
	return strconv.Itoa(int(bytes[0])) + "." +
		strconv.Itoa(int(bytes[1])) + "." +
		strconv.Itoa(int(bytes[2])) + "." +
		strconv.Itoa(int(bytes[3]))
}

func StringMAC(bytes []uint8) string {
	const hexDigit = "0123456789abcdef"
	buf := make([]byte, 0, len(bytes)*3-1)
	for i, b := range bytes {
		if i > 0 {
			buf = append(buf, ':')
		}
		buf = append(buf, hexDigit[b>>4])
		buf = append(buf, hexDigit[b&0xF])
	}
	return string(buf)
}

func StringIPProtocol(bytes []uint8) string {
	if entry, ok := net2.IPProtocolMap[int(bytes[0])]; ok {
		return entry.Keyword
	}
	return ""
}
