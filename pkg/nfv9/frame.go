package nfv9

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

type Frame struct {
	Header   Header
	FlowSets []FlowSet
}

type Header struct {
	Version        uint16
	Count          uint16
	systemUptime   uint32
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

func (p *TemplateFlowSet) read(f *Framer, fsid uint16) error {
	p.FlowSetID = fsid
	if err := binary.Read(f.buf, binary.BigEndian, &p.Length); err != nil {
		return err
	}
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

type DataFlowSet struct {
	FlowSetID uint16 // maps to a previously generated TemplateID.
	Length    uint16
	Fields    []uint8
}

func (p *DataFlowSet) read(f *Framer, fsid uint16) error {
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

type OptionsTemplateFlowSet struct {
	FlowSetID         uint16 // always 1
	Length            uint16
	TemplateID        uint16
	OptionScopeLength uint16
	OptionLength      uint16
	ScopeFields       []FieldTL
	OptionFields      []FieldTL
}

type OptionsDataFlowSet struct {
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
func (f *Framer) ReadFrame() (frame Frame, err error) {
	err = nil
	frame = Frame{}

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
			fs := TemplateFlowSet{}
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
			err = fmt.Errorf("Unimplemented: OptionsTemplateFlowSet")
			return
		case fsid > 255:
			fs := DataFlowSet{}
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
