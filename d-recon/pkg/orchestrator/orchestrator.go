package orchestrator

import (
	"d-recon/internal/core"
	"d-recon/internal/modules/osint"
	"d-recon/internal/modules/ports"
	"d-recon/internal/modules/subdomains"
	"d-recon/internal/modules/vulnerabilities"
	"d-recon/internal/modules/web"
	"d-recon/internal/utils"
	"sync"
	"time"
)

type Orchestrator struct {
	modules []core.Module
	config  *core.Config
}

func NewOrchestrator(config *core.Config) *Orchestrator {
	return &Orchestrator{
		config: config,
		modules: []core.Module{
			&subdomains.SubfinderRunner{},
			&subdomains.DNSResolver{},
			&ports.NmapRunner{},
			&web.WebScanner{},
			&vulnerabilities.NucleiRunner{},
			&osint.OSINTScanner{},
			// Здесь будут добавляться другие модули
		},
	}
}

func (o *Orchestrator) Run(target string) *core.ReconResults {
	utils.Logger.Infof("Starting reconnaissance with %d modules", len(o.modules))

	results := &core.ReconResults{
		Target:    target,
		StartTime: time.Now(),
		Modules:   make(map[string]core.ModuleResult),
	}

	var wg sync.WaitGroup
	resultsChan := make(chan core.ModuleResult, len(o.modules))

	// Запускаем модули параллельно
	for _, module := range o.modules {
		if module.IsEnabled() {
			wg.Add(1)
			go func(m core.Module) {
				defer wg.Done()

				utils.Logger.Debugf("Running module: %s", m.Name())
				result, err := m.Run(target, o.config)
				if err != nil {
					utils.Logger.Errorf("Module %s failed: %v", m.Name(), err)
					result = &core.ModuleResult{
						Module:    m.Name(),
						Timestamp: time.Now(),
						Error:     err.Error(),
					}
				}

				resultsChan <- *result
			}(module)
		}
	}

	// Ждем завершения всех модулей
	wg.Wait()
	close(resultsChan)

	// Собираем результаты
	for result := range resultsChan {
		results.Modules[result.Module] = result
	}

	results.EndTime = time.Now()
	utils.Logger.Infof("Reconnaissance completed in %v", results.EndTime.Sub(results.StartTime))

	return results
}
