package nfv9

// TemplateCache is used to store templates.
type TemplateCache struct {
	templates map[uint16]*Template
}

func NewTemplateCache() *TemplateCache {
	return &TemplateCache{
		templates: make(map[uint16]*Template),
	}
}

func (tc *TemplateCache) Exists(tid uint16) bool {
	_, ok := tc.templates[tid]
	return ok
}

func (tc *TemplateCache) Add(template *Template) {
	tc.templates[template.TemplateID] = template
}

func (tc *TemplateCache) Get(tid uint16) (template *Template, ok bool) {
	t, ok := tc.templates[tid]
	if !ok {
		return nil, false
	}
	return t, true
}
