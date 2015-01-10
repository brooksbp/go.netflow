package nfv9

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

type NFv9Frame struct {
	Header   NFv9Header
	FlowSets []FlowSet
}

type FlowSet interface{}

type NFv9Header struct {
	Version        uint16
	Count          uint16
	SystemUptime   uint32
	UNIXSeconds    uint32
	SequenceNumber uint32
	SourceID       uint32
}

func (p *NFv9Header) read(f *Framer) error {
	if err := binary.Read(f.buf, binary.BigEndian, p); err != nil {
		return err
	}
	return nil
}

type NFv9FieldTL struct {
	Type   uint16
	Length uint16
}

func (p *NFv9FieldTL) read(f *Framer) error {
	if err := binary.Read(f.buf, binary.BigEndian, p); err != nil {
		return err
	}
	return nil
}

type NFv9Template struct {
	TemplateID uint16 // always 0-255
	FieldCount uint16
	Fields     []NFv9FieldTL
}

func (p *NFv9Template) size() int {
	size := binary.Size(p.TemplateID)
	size += binary.Size(p.FieldCount)
	size += int(p.FieldCount) * binary.Size(NFv9FieldTL{})
	return size
}

func (p *NFv9Template) read(f *Framer) error {
	if err := binary.Read(f.buf, binary.BigEndian, &p.TemplateID); err != nil {
		return err
	}
	if err := binary.Read(f.buf, binary.BigEndian, &p.FieldCount); err != nil {
		return err
	}
	for i := 0; i < int(p.FieldCount); i++ {
		field := NFv9FieldTL{}
		if err := field.read(f); err != nil {
			return err
		}
		p.Fields = append(p.Fields, field)
	}
	return nil
}

type NFv9TemplateFlowSet struct {
	FlowSetID uint16 // always 0
	Length    uint16
	Templates []NFv9Template
}

func (p *NFv9TemplateFlowSet) read(f *Framer, fsid uint16) error {
	p.FlowSetID = fsid
	if err := binary.Read(f.buf, binary.BigEndian, &p.Length); err != nil {
		return err
	}
	bytesRemaining := int(p.Length) - binary.Size(p.FlowSetID) - binary.Size(p.Length)
	for bytesRemaining > 0 {
		template := NFv9Template{}
		if err := template.read(f); err != nil {
			return err
		}
		p.Templates = append(p.Templates, template)
		bytesRemaining -= template.size()
	}
	return nil
}

type NFv9DataFlowSet struct {
	FlowSetID uint16 // maps to a previously generated TemplateID.
	Length    uint16
	Fields    []uint8
}

func (p *NFv9DataFlowSet) read(f *Framer, fsid uint16) error {
	p.FlowSetID = fsid
	if err := binary.Read(f.buf, binary.BigEndian, &p.Length); err != nil {
		return err
	}
	bytesRemaining := int(p.Length) - binary.Size(p.FlowSetID) - binary.Size(p.Length)
	for bytesRemaining > 0 {
		var field uint8
		if err := binary.Read(f.buf, binary.BigEndian, &field); err != nil {
			return err
		}
		p.Fields = append(p.Fields, field)
		bytesRemaining -= binary.Size(field)
	}
	return nil
}

type NFv9OptionsTemplateFlowSet struct {
	FlowSetID         uint16 // always 1
	Length            uint16
	TemplateID        uint16
	OptionScopeLength uint16
	OptionLength      uint16
	ScopeFields       []NFv9FieldTL
	OptionFields      []NFv9FieldTL
}

type NFv9OptionsDataFlowSet struct {
	FlowSetID uint16 // maps to a previously generated Options TemplateID
	Length    uint16
	Fields    []uint16
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
func (f *Framer) ReadFrame() (frame NFv9Frame, err error) {
	err = nil
	frame = NFv9Frame{}

	if err = frame.Header.read(f); err != nil {
		return
	}

	recordsRemaining := int(frame.Header.Count)
	for recordsRemaining > 0 {
		var fsid uint16
		if err = binary.Read(f.buf, binary.BigEndian, &fsid); err != nil {
			return
		}
		switch {
		case fsid == 0:
			fs := NFv9TemplateFlowSet{}
			if err = fs.read(f, fsid); err != nil {
				return
			}

			// Add new templates to the TemplateCache.
			for _, template := range fs.Templates {
				if !f.template_cache.Exists(template.TemplateID) {
					f.template_cache.Add(&template)
				}
			}

			frame.FlowSets = append(frame.FlowSets, fs)
			recordsRemaining -= len(fs.Templates)
		case fsid == 1:
			err = fmt.Errorf("Unimplemented: NFv9OptionsTemplateFlowSet")
			return
		case fsid > 255:
			fs := NFv9DataFlowSet{}
			if err = fs.read(f, fsid); err != nil {
				return
			}

			template, ok := f.template_cache.Get(fs.FlowSetID)
			if !ok {
				err = fmt.Errorf("Cannot parse DataFlowSet. Unknown TemplateID=%d", fs.FlowSetID)
				return
			}

			frame.FlowSets = append(frame.FlowSets, fs)
			recordsRemaining -= len(fs.Fields) / int(template.FieldCount)
		default:
			err = fmt.Errorf("Unknown FlowSet Id: %d", fsid)
			return
		}
	}
	return
}
