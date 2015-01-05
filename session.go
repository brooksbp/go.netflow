package nfv9

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
