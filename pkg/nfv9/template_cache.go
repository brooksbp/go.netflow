package nfv9

// TemplateCache is used to store templates.
type TemplateCache struct {
	templates map[uint16]*NFv9Template
}

func NewTemplateCache() *TemplateCache {
	return &TemplateCache{
		templates: make(map[uint16]*NFv9Template),
	}
}

func (tc *TemplateCache) Exists(tid uint16) bool {
	_, ok := tc.templates[tid]
	return ok
}

func (tc *TemplateCache) Add(template *NFv9Template) {
	tc.templates[template.TemplateID] = template
}

func (tc *TemplateCache) Get(tid uint16) (template *NFv9Template, ok bool) {
	t, ok := tc.templates[tid]
	if !ok {
		return nil, false
	}
	return t, true
}
