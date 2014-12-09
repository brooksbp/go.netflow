package nfv9

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

// RFC 3954: Cisco Systems NetFlow Services Export Version 9

// Session contains the NetFlow collector's context.
type Session struct {
	templates map[int]NFv9Template
}

func NewSession() *Session {
	return &Session{
		templates: make(map[int]NFv9Template),
	}
}

// OnReadTemplate adds new templates to the session's template map.
func (s *Session) OnReadTemplate(fs *NFv9TemplateFlowSet) {
	for _, t := range fs.Templates {
		tid := int(t.TemplateID)
		if _, ok := s.templates[tid]; !ok {
			s.templates[tid] = t
		}
	}
}

// -----------------------------------------------------------------------------

// Framer is used to parse received data into a NetFlow frame.
type Framer struct {
	buf     *bytes.Buffer
	session *Session
}

func NewFramer(b *bytes.Buffer, s *Session) *Framer {
	return &Framer{
		buf:     b,
		session: s,
	}
}

// -----------------------------------------------------------------------------
type NFv9Frame struct {
	Header   NFv9Header
	FlowSets []FlowSet
}

type FlowSet interface{}

// -----------------------------------------------------------------------------

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
			f.session.OnReadTemplate(&fs)
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
			tid := int(fs.FlowSetID)
			template, ok := f.session.templates[tid]
			if !ok {
				err = fmt.Errorf("Unknown template=%d", tid)
				return
			}
			frame.FlowSets = append(frame.FlowSets, fs)
			recordsRemaining -= len(fs.Fields) / int(template.FieldCount)
			// TODO: parse NFv9DataFlowSet or NFv9OptionsDataFlowSet
			// depenending on fsid in existing template map
		default:
			err = fmt.Errorf("Unknown FlowSet Id: %d", fsid)
			return
		}
	}
	return
}

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
	Fields    []uint16
}

func (p *NFv9DataFlowSet) read(f *Framer, fsid uint16) error {
	p.FlowSetID = fsid
	if err := binary.Read(f.buf, binary.BigEndian, &p.Length); err != nil {
		return err
	}
	bytesRemaining := int(p.Length) - binary.Size(p.FlowSetID) - binary.Size(p.Length)
	for bytesRemaining > 0 {
		var field uint16
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
