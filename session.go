package nfv9

type Session struct {
	templates map[int]NFv9Template
}

func NewSession() *Session {
	return &Session{
		templates: make(map[int]NFv9Template),
	}
}

func (s *Session) OnReadTemplate(fs *NFv9TemplateFlowSet) {
	for _, t := range fs.Templates {
		tid := int(t.TemplateID)
		if _, ok := s.templates[tid]; !ok {
			s.templates[tid] = t
		}
	}
}
