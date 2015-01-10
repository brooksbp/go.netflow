package nfv9

import (
	"fmt"
)

type Session struct {
	templates map[int]NFv9Template
}

func NewSession() *Session {
	return &Session{
		templates: make(map[int]NFv9Template),
	}
}

// OnReadTemplate adds new templates to the session's templates map.
//
// The template id is used to determine whether to store the template. If the
// template id has been seen before, the template is not checked for any change.
func (s *Session) OnReadTemplate(fs *NFv9TemplateFlowSet) {
	for _, t := range fs.Templates {
		tid := int(t.TemplateID)
		if _, ok := s.templates[tid]; !ok {
			s.templates[tid] = t
		}
	}
}

func (s *Session) OnReadData(fs *NFv9DataFlowSet, template *NFv9Template) {
	i := 0
	for _, field := range template.Fields {
		ty := int(field.Type)
		len := int(field.Length)

		entry := FieldMap[ty]

		fmt.Print(entry.Name, ": ", entry.String(fs.Fields[i:i+len]), " ")

		i += len
	}
	fmt.Println()
}
