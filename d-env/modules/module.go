package modules

type Module interface {
	Gather() (ModuleResult, error)
}

type ModuleResult struct {
	Data    map[string]interface{}
	Display string
	Error   error
}
