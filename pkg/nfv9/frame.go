package nfv9

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strconv"
)

// NetFlow v9 export packet.
type Frame struct {
	Header   Header
	FlowSets []FlowSet
}

type Header struct {
	// The version of NetFlow records exported in this packet.
	Version uint16
	// Number of FlowSet records (both template and data) contained within
	// this packet.
	Count uint16
	// Time in milliseconds since this device was first booted.
	SystemUptime uint32
	// Seconds since 0000 Coordinated Universal Time (UTC) 1970
	UNIXSeconds    uint32
	SequenceNumber uint32
	SourceID       uint32
}

type FlowSet interface{}

func (p *Header) read(f *Framer) error {
	if err := binary.Read(f.buf, binary.BigEndian, p); err != nil {
		return err
	}
	return nil
}

func (p *Header) String() string {
	return "Ver=" + strconv.Itoa(int(p.Version)) +
		" Count=" + strconv.Itoa(int(p.Count)) +
		" SystemUptime=" + strconv.Itoa(int(p.SystemUptime)) +
		" UNIXSeconds=" + strconv.Itoa(int(p.UNIXSeconds)) +
		" SeqNo=" + strconv.Itoa(int(p.SequenceNumber)) +
		" SourceID=" + strconv.Itoa(int(p.SourceID)) +
		" : "
}

type FieldTL struct {
	Type   uint16
	Length uint16
}

func (p *FieldTL) read(f *Framer) error {
	if err := binary.Read(f.buf, binary.BigEndian, p); err != nil {
		return err
	}
	return nil
}

type Template struct {
	TemplateID uint16 // always 0-255
	FieldCount uint16
	Fields     []FieldTL
}

func (p *Template) size() int {
	size := binary.Size(p.TemplateID)
	size += binary.Size(p.FieldCount)
	size += int(p.FieldCount) * binary.Size(FieldTL{})
	return size
}

// fieldsSize returns the total number of bytes of data specified by the
// template.
func (p *Template) fieldsSize() int {
	var n int
	for _, field := range p.Fields {
		n += int(field.Length)
	}
	return n
}

func (p *Template) read(f *Framer) error {
	if err := binary.Read(f.buf, binary.BigEndian, &p.TemplateID); err != nil {
		return err
	}
	if err := binary.Read(f.buf, binary.BigEndian, &p.FieldCount); err != nil {
		return err
	}
	for i := 0; i < int(p.FieldCount); i++ {
		field := FieldTL{}
		if err := field.read(f); err != nil {
			return err
		}
		p.Fields = append(p.Fields, field)
	}
	return nil
}

type TemplateFlowSet struct {
	FlowSetID uint16 // always 0
	Length    uint16
	Templates []Template
}

func (p *TemplateFlowSet) read(f *Framer, fsId uint16, length uint16) error {
	p.FlowSetID = fsId
	p.Length = length

	bytesRemaining := int(p.Length) - binary.Size(p.FlowSetID) - binary.Size(p.Length)
	for bytesRemaining > 0 {
		template := Template{}
		if err := template.read(f); err != nil {
			return err
		}
		p.Templates = append(p.Templates, template)
		bytesRemaining -= template.size()
	}
	return nil
}

type DataRecord struct {
	Fields []uint8
}

type DataFlowSet struct {
	// FlowSetID maps to a (previously received) template ID.
	// Note: parsing does not validate this!
	FlowSetID uint16
	// Length in bytes of this DataFlowSet.
	Length uint16
	// N records x N fields, as defined by the template.
	Records []DataRecord
}

func (p *DataFlowSet) read(f *Framer, fsId uint16, length uint16, template *Template) (int, error) {
	p.FlowSetID = fsId
	p.Length = length

	bytesRemaining := int(p.Length) - binary.Size(p.FlowSetID) - binary.Size(p.Length)

	recordSize := template.fieldsSize()

	count := 0
	for bytesRemaining >= recordSize {
		// Eat a record
		dr := DataRecord{}

		n := recordSize
		for n > 0 {
			// TODO: just copy bytes into dr.Fields?
			var field uint8
			if err := binary.Read(f.buf, binary.BigEndian, &field); err != nil {
				return 0, err
			}
			dr.Fields = append(dr.Fields, field)
			n -= 1
		}
		p.Records = append(p.Records, dr)
		bytesRemaining -= recordSize
		count += 1
	}
	// Eat padding.
	for bytesRemaining > 0 {
		var padding uint8
		if err := binary.Read(f.buf, binary.BigEndian, &padding); err != nil {
			return 0, err
		}
		bytesRemaining -= binary.Size(padding)
	}
	return count, nil
}

type Framer struct {
	buf            *bytes.Buffer
	template_cache *TemplateCache
}

func NewFramer(b *bytes.Buffer, tc *TemplateCache) *Framer {
	return &Framer{
		buf:            b,
		template_cache: tc,
	}
}

// ReadFrame parses framer's buffer data and returns a NetFlow frame.
func (f *Framer) ReadFrame() (frame Frame, err error) {
	err = nil
	frame = Frame{}

	// Read Header
	if err = frame.Header.read(f); err != nil {
		return
	}

	// Read FlowSets
	count := int(frame.Header.Count)
	for count > 0 && f.buf.Len() > 0 {
		// Parse a FlowSet record.
		var fsId uint16
		var length uint16
		if err = binary.Read(f.buf, binary.BigEndian, &fsId); err != nil {
			return
		}
		if err = binary.Read(f.buf, binary.BigEndian, &length); err != nil {
			return
		}

		switch {
		case fsId == 0:
			tfs := TemplateFlowSet{}
			if err = tfs.read(f, fsId, length); err != nil {
				return
			}

			// Add new templates to the TemplateCache.
			for _, template := range tfs.Templates {
				template := template
				if !f.template_cache.Exists(template.TemplateID) {
					f.template_cache.Add(&template)
				}
			}

			frame.FlowSets = append(frame.FlowSets, tfs)
			count -= 1
			break
		case fsId > 255:
			template, ok := f.template_cache.Get(fsId)
			if !ok {
				err = fmt.Errorf("Cannot parse DataFlowSet: unknown TemplateID=%d", fsId)
				return
			}
			dfs := DataFlowSet{}
			var cnt int
			cnt, err = dfs.read(f, fsId, length, template)
			if err != nil {
				return
			}
			frame.FlowSets = append(frame.FlowSets, dfs)
			count -= cnt
			break
		}
	}
	return
}
