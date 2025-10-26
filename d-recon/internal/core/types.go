package core

import "time"

type Config struct {
	Target       string        `yaml:"target" json:"target"`
	Profile      string        `yaml:"profile" json:"profile"`
	OutputFormat string        `yaml:"output_format" json:"output_format"`
	OutputDir    string        `yaml:"output_dir" json:"output_dir"`
	Modules      []string      `yaml:"modules" json:"modules"`
	RateLimit    int           `yaml:"rate_limit" json:"rate_limit"`
	Timeout      time.Duration `yaml:"timeout" json:"timeout"`
	Verbose      bool          `yaml:"verbose" json:"verbose"`
}

type ModuleResult struct {
	Module    string      `json:"module"`
	Data      interface{} `json:"data"`
	Timestamp time.Time   `json:"timestamp"`
	Error     string      `json:"error,omitempty"`
}

type ReconResults struct {
	Target    string                  `json:"target"`
	StartTime time.Time               `json:"start_time"`
	EndTime   time.Time               `json:"end_time"`
	Modules   map[string]ModuleResult `json:"modules"`
}

type Port struct {
	Number   int    `json:"number"`
	Protocol string `json:"protocol"`
	Service  string `json:"service"`
	State    string `json:"state"`
}

type WebURL struct {
	URL    string `json:"url"`
	Status int    `json:"status"`
	Title  string `json:"title,omitempty"`
}

type Module interface {
	Name() string
	Run(target string, config *Config) (*ModuleResult, error)
	IsEnabled() bool
}
