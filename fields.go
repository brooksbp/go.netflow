package nfv9

import (
	"fmt"
)

type FieldTypeEntry struct {
	Name  string
	Print func(d8 []uint8)
}

func PrintDefault(d8 []uint8) {
	for _, b := range d8 {
		fmt.Print(b, " ")
	}
}
func PrintIPv4(d8 []uint8) {
	fmt.Print(d8[0], ".", d8[1], ".", d8[2], ".", d8[3])
}
func PrintMAC(d8 []uint8) {
	fmt.Printf("%02x:%02x:%02x:%02x:%02x:%02x", d8[0], d8[1], d8[2], d8[3], d8[4], d8[5])
}

var FieldMap = map[int]FieldTypeEntry{
	1:   FieldTypeEntry{Name: "IN_BYTES", Print: PrintDefault},
	2:   FieldTypeEntry{Name: "IN_PKTS", Print: PrintDefault},
	3:   FieldTypeEntry{Name: "FLOWS", Print: PrintDefault},
	4:   FieldTypeEntry{Name: "PROTOCOL", Print: PrintDefault},
	5:   FieldTypeEntry{Name: "SRC_TOS", Print: PrintDefault},
	6:   FieldTypeEntry{Name: "TCP_FLAGS", Print: PrintDefault},
	7:   FieldTypeEntry{Name: "L4_SRC_PORT", Print: PrintDefault},
	8:   FieldTypeEntry{Name: "IPV4_SRC_ADDR", Print: PrintIPv4},
	9:   FieldTypeEntry{Name: "SRC_MASK", Print: PrintDefault},
	10:  FieldTypeEntry{Name: "INPUT_SNMP", Print: PrintDefault},
	11:  FieldTypeEntry{Name: "L4_DST_PORT", Print: PrintDefault},
	12:  FieldTypeEntry{Name: "IPV4_DST_ADDR", Print: PrintIPv4},
	13:  FieldTypeEntry{Name: "DST_MASK", Print: PrintDefault},
	14:  FieldTypeEntry{Name: "OUTPUT_SNMP", Print: PrintDefault},
	15:  FieldTypeEntry{Name: "IPV4_NEXT_HOP", Print: PrintIPv4},
	16:  FieldTypeEntry{Name: "SRC_AS", Print: PrintDefault},
	17:  FieldTypeEntry{Name: "DST_AS", Print: PrintDefault},
	18:  FieldTypeEntry{Name: "BGP_IPV4_NEXT_HOP", Print: PrintDefault},
	19:  FieldTypeEntry{Name: "MUL_DST_PKTS", Print: PrintDefault},
	20:  FieldTypeEntry{Name: "MUL_DST_BYTES", Print: PrintDefault},
	21:  FieldTypeEntry{Name: "LAST_SWITCHED", Print: PrintDefault},
	22:  FieldTypeEntry{Name: "FIRST_SWITCHED", Print: PrintDefault},
	23:  FieldTypeEntry{Name: "OUT_BYTES", Print: PrintDefault},
	24:  FieldTypeEntry{Name: "OUT_PKTS", Print: PrintDefault},
	25:  FieldTypeEntry{Name: "MIN_PKT_LNGTH", Print: PrintDefault},
	26:  FieldTypeEntry{Name: "MAX_PKT_LNGTH", Print: PrintDefault},
	27:  FieldTypeEntry{Name: "IPV6_SRC_ADDR", Print: PrintDefault},
	28:  FieldTypeEntry{Name: "IPV6_DST_ADDR", Print: PrintDefault},
	29:  FieldTypeEntry{Name: "IPV6_SRC_MASK", Print: PrintDefault},
	30:  FieldTypeEntry{Name: "IPV6_DST_MASK", Print: PrintDefault},
	31:  FieldTypeEntry{Name: "IPV6_FLOW_LABEL", Print: PrintDefault},
	32:  FieldTypeEntry{Name: "ICMP_TYPE", Print: PrintDefault},
	33:  FieldTypeEntry{Name: "MUL_IGMP_TYPE", Print: PrintDefault},
	34:  FieldTypeEntry{Name: "SAMPLING_INTERVAL", Print: PrintDefault},
	35:  FieldTypeEntry{Name: "SAMPLING_ALGORITHM", Print: PrintDefault},
	36:  FieldTypeEntry{Name: "FLOW_ACTIVE_TIMEOUT", Print: PrintDefault},
	37:  FieldTypeEntry{Name: "FLOW_INACTIVE_TIMEOUT", Print: PrintDefault},
	38:  FieldTypeEntry{Name: "ENGINE_TYPE", Print: PrintDefault},
	39:  FieldTypeEntry{Name: "ENGINE_ID", Print: PrintDefault},
	40:  FieldTypeEntry{Name: "TOTAL_BYTES_EXP", Print: PrintDefault},
	41:  FieldTypeEntry{Name: "TOTAL_PKTS_EXP", Print: PrintDefault},
	42:  FieldTypeEntry{Name: "TOTAL_FLOWS_EXP", Print: PrintDefault},
	43:  FieldTypeEntry{Name: "*Vendor Proprietary*", Print: PrintDefault},
	44:  FieldTypeEntry{Name: "IPV4_SRC_PREFIX", Print: PrintDefault},
	45:  FieldTypeEntry{Name: "IPV4_DST_PREFIX", Print: PrintDefault},
	46:  FieldTypeEntry{Name: "MPLS_TOP_LABEL_TYPE", Print: PrintDefault},
	47:  FieldTypeEntry{Name: "MPLS_TOP_LABEL_IP_ADDR", Print: PrintDefault},
	48:  FieldTypeEntry{Name: "FLOW_SAMPLER_ID", Print: PrintDefault},
	49:  FieldTypeEntry{Name: "FLOW_SAMPLER_MODE", Print: PrintDefault},
	50:  FieldTypeEntry{Name: "FLOW_SAMPLER_RANDOM_INTERVAL", Print: PrintDefault},
	51:  FieldTypeEntry{Name: "*Vendor Proprietary*", Print: PrintDefault},
	52:  FieldTypeEntry{Name: "MIN_TTL", Print: PrintDefault},
	53:  FieldTypeEntry{Name: "MAX_TTL", Print: PrintDefault},
	54:  FieldTypeEntry{Name: "IPV4_IDENT", Print: PrintDefault},
	55:  FieldTypeEntry{Name: "DST_TOS", Print: PrintDefault},
	56:  FieldTypeEntry{Name: "IN_SRC_MAC", Print: PrintMAC},
	57:  FieldTypeEntry{Name: "OUT_DST_MAC", Print: PrintMAC},
	58:  FieldTypeEntry{Name: "SRC_VLAN", Print: PrintDefault},
	59:  FieldTypeEntry{Name: "DST_VLAN", Print: PrintDefault},
	60:  FieldTypeEntry{Name: "IP_PROTOCOL_VERSION", Print: PrintDefault},
	61:  FieldTypeEntry{Name: "DIRECTION", Print: PrintDefault},
	62:  FieldTypeEntry{Name: "IPV6_NEXT_HOP", Print: PrintDefault},
	63:  FieldTypeEntry{Name: "BGP_IPV6_NEXT_HOP", Print: PrintDefault},
	64:  FieldTypeEntry{Name: "IPV6_OPTIONS_HEADERS", Print: PrintDefault},
	65:  FieldTypeEntry{Name: "*Vendor Proprietary*", Print: PrintDefault},
	66:  FieldTypeEntry{Name: "*Vendor Proprietary*", Print: PrintDefault},
	67:  FieldTypeEntry{Name: "*Vendor Proprietary*", Print: PrintDefault},
	68:  FieldTypeEntry{Name: "*Vendor Proprietary*", Print: PrintDefault},
	69:  FieldTypeEntry{Name: "*Vendor Proprietary*", Print: PrintDefault},
	70:  FieldTypeEntry{Name: "MPLS_LABEL_1", Print: PrintDefault},
	71:  FieldTypeEntry{Name: "MPLS_LABEL_2", Print: PrintDefault},
	72:  FieldTypeEntry{Name: "MPLS_LABEL_3", Print: PrintDefault},
	73:  FieldTypeEntry{Name: "MPLS_LABEL_4", Print: PrintDefault},
	74:  FieldTypeEntry{Name: "MPLS_LABEL_5", Print: PrintDefault},
	75:  FieldTypeEntry{Name: "MPLS_LABEL_6", Print: PrintDefault},
	76:  FieldTypeEntry{Name: "MPLS_LABEL_7", Print: PrintDefault},
	77:  FieldTypeEntry{Name: "MPLS_LABEL_8", Print: PrintDefault},
	78:  FieldTypeEntry{Name: "MPLS_LABEL_9", Print: PrintDefault},
	79:  FieldTypeEntry{Name: "MPLS_LABEL_10", Print: PrintDefault},
	80:  FieldTypeEntry{Name: "IN_DST_MAC", Print: PrintMAC},
	81:  FieldTypeEntry{Name: "OUT_SRC_MAC", Print: PrintMAC},
	82:  FieldTypeEntry{Name: "IF_NAME", Print: PrintDefault},
	83:  FieldTypeEntry{Name: "IF_DESC", Print: PrintDefault},
	84:  FieldTypeEntry{Name: "SAMPLER_NAME", Print: PrintDefault},
	85:  FieldTypeEntry{Name: "IN_PERMANENT_BYTES", Print: PrintDefault},
	86:  FieldTypeEntry{Name: "IN_PERMANENT_PKTS", Print: PrintDefault},
	87:  FieldTypeEntry{Name: "*Vendor Proprietary", Print: PrintDefault},
	88:  FieldTypeEntry{Name: "FRAGMENT_OFFSET", Print: PrintDefault},
	89:  FieldTypeEntry{Name: "FORWARDING_STATUS", Print: PrintDefault},
	90:  FieldTypeEntry{Name: "MPLS_PAL_RD", Print: PrintDefault},
	91:  FieldTypeEntry{Name: "MPLS_PREFIX_LEN", Print: PrintDefault},
	92:  FieldTypeEntry{Name: "SRC_TRAFFIC_INDEX", Print: PrintDefault},
	93:  FieldTypeEntry{Name: "DST_TRAFFIC_INDEX", Print: PrintDefault},
	94:  FieldTypeEntry{Name: "APPLICATION_DESCRIPTION", Print: PrintDefault},
	95:  FieldTypeEntry{Name: "APPLICATION_TAG", Print: PrintDefault},
	96:  FieldTypeEntry{Name: "APPLICATION_NAME", Print: PrintDefault},
	97:  FieldTypeEntry{Name: "postipDiffServCodePoint", Print: PrintDefault},
	98:  FieldTypeEntry{Name: "replication factor", Print: PrintDefault},
	99:  FieldTypeEntry{Name: "DEPRECATED", Print: PrintDefault},
	100: FieldTypeEntry{Name: "layer2packetSectionOffset", Print: PrintDefault},
	101: FieldTypeEntry{Name: "layer2packetSectionSize", Print: PrintDefault},
	102: FieldTypeEntry{Name: "layer2packetSectionData", Print: PrintDefault},
}
