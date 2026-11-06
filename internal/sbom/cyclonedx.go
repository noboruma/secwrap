package sbom

// Minimal CycloneDX 1.6 model (JSON). Only the fields we emit.

type BOM struct {
	BOMFormat    string       `json:"bomFormat"`
	SpecVersion  string       `json:"specVersion"`
	SerialNumber string       `json:"serialNumber"`
	Version      int          `json:"version"`
	Metadata     Metadata     `json:"metadata"`
	Components   []Component  `json:"components"`
	Services     []Service    `json:"services,omitempty"`
	Dependencies []Dependency `json:"dependencies,omitempty"`
}

type Metadata struct {
	Timestamp  string     `json:"timestamp"`
	Tools      *Tools     `json:"tools,omitempty"`
	Component  *Component `json:"component,omitempty"`
	Properties []Property `json:"properties,omitempty"`
}

type Tools struct {
	Components []Component `json:"components"`
}

type Component struct {
	BOMRef     string     `json:"bom-ref,omitempty"`
	Type       string     `json:"type"` // application | library | operating-system | file
	Name       string     `json:"name"`
	Version    string     `json:"version,omitempty"`
	PURL       string     `json:"purl,omitempty"`
	Hashes     []Hash     `json:"hashes,omitempty"`
	Licenses   []License  `json:"licenses,omitempty"`
	Supplier   *Entity    `json:"supplier,omitempty"`
	Evidence   *Evidence  `json:"evidence,omitempty"`
	Properties []Property `json:"properties,omitempty"`
}

type Entity struct {
	Name string `json:"name"`
}

type License struct {
	Expression string `json:"expression,omitempty"`
}

type Hash struct {
	Alg     string `json:"alg"`
	Content string `json:"content"`
}

type Evidence struct {
	Occurrences []Occurrence `json:"occurrences,omitempty"`
}

type Occurrence struct {
	Location string `json:"location"`
}

type Property struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type Dependency struct {
	Ref       string   `json:"ref"`
	DependsOn []string `json:"dependsOn,omitempty"`
}

// Service describes an observed network peer (filled by `secwrap run`).
type Service struct {
	BOMRef     string     `json:"bom-ref,omitempty"`
	Name       string     `json:"name"`
	Endpoints  []string   `json:"endpoints,omitempty"`
	Properties []Property `json:"properties,omitempty"`
}
