package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"time"

	"d-env/modules"
	"d-env/modules/dependencies"
	"d-env/modules/docker"
	"d-env/modules/git"
	"d-env/modules/ml"
	"d-env/modules/project"
	"d-env/modules/security"

	"github.com/urfave/cli/v2"
)

type OutputFormat string

const (
	FormatText OutputFormat = "text"
	FormatJSON OutputFormat = "json"
)

type Config struct {
	EnabledModules  []string
	ExcludedModules []string
	OutputFormat    OutputFormat
	OutputFile      string
	FullTree        bool
	ShowDataSize    bool
	Quiet           bool
}

func main() {
	app := &cli.App{
		Name:  "d-env",
		Usage: "Comprehensive project environment analysis tool",
		Flags: []cli.Flag{
			&cli.StringSliceFlag{
				Name:    "modules",
				Aliases: []string{"m"},
				Usage:   "Specific modules to run (comma-separated)",
			},
			&cli.StringSliceFlag{
				Name:    "exclude-modules",
				Aliases: []string{"e"},
				Usage:   "Modules to exclude (comma-separated)",
			},
			&cli.StringFlag{
				Name:    "format",
				Aliases: []string{"f"},
				Usage:   "Output format: text or json",
				Value:   "text",
			},
			&cli.StringFlag{
				Name:    "output",
				Aliases: []string{"o"},
				Usage:   "Output file path",
			},
			&cli.BoolFlag{
				Name:  "full-tree",
				Usage: "Show full directory tree without ignoring common directories",
			},
			&cli.BoolFlag{
				Name:  "show-data-size",
				Usage: "Show size of data directories (may be slow)",
			},
			&cli.BoolFlag{
				Name:    "quiet",
				Aliases: []string{"q"},
				Usage:   "Only show critical information and warnings",
			},
		},
		Action: run,
	}

	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}

func run(c *cli.Context) error {
	config := &Config{
		EnabledModules:  c.StringSlice("modules"),
		ExcludedModules: c.StringSlice("exclude-modules"),
		OutputFormat:    OutputFormat(c.String("format")),
		OutputFile:      c.String("output"),
		FullTree:        c.Bool("full-tree"),
		ShowDataSize:    c.Bool("show-data-size"),
		Quiet:           c.Bool("quiet"),
	}

	results, err := gatherInfo(config)
	if err != nil {
		return err
	}

	output, err := formatOutput(results, config)
	if err != nil {
		return err
	}

	if config.OutputFile != "" {
		return os.WriteFile(config.OutputFile, []byte(output), 0644)
	}

	fmt.Println(output)
	return nil
}

func gatherInfo(config *Config) (map[string]modules.ModuleResult, error) {
	allModules := map[string]modules.Module{
		"git":          &git.Module{},
		"docker":       &docker.Module{},
		"project":      &project.Module{FullTree: config.FullTree},
		"dependencies": &dependencies.Module{},
		"security":     &security.Module{},
		"ml":           &ml.Module{ShowDataSize: config.ShowDataSize},
	}

	// Filter modules based on config
	modulesToRun := filterModules(allModules, config)

	var wg sync.WaitGroup
	results := make(map[string]modules.ModuleResult)
	resultMutex := &sync.Mutex{}

	for moduleName, module := range modulesToRun {
		wg.Add(1)
		go func(name string, mod modules.Module) {
			defer wg.Done()

			result, err := mod.Gather()
			if err != nil && !config.Quiet {
				result = modules.ModuleResult{
					Data:  map[string]interface{}{"error": err.Error()},
					Error: err,
				}
			}

			resultMutex.Lock()
			results[name] = result
			resultMutex.Unlock()
		}(moduleName, module)
	}

	wg.Wait()
	return results, nil
}

func filterModules(allModules map[string]modules.Module, config *Config) map[string]modules.Module {
	if len(config.EnabledModules) > 0 {
		filtered := make(map[string]modules.Module)
		for _, name := range config.EnabledModules {
			if module, exists := allModules[name]; exists {
				filtered[name] = module
			}
		}
		return filtered
	}

	if len(config.ExcludedModules) > 0 {
		filtered := make(map[string]modules.Module)
		for name, module := range allModules {
			excluded := false
			for _, excludedName := range config.ExcludedModules {
				if name == excludedName {
					excluded = true
					break
				}
			}
			if !excluded {
				filtered[name] = module
			}
		}
		return filtered
	}

	return allModules
}

func formatOutput(results map[string]modules.ModuleResult, config *Config) (string, error) {
	if config.OutputFormat == FormatJSON {
		jsonData, err := json.MarshalIndent(results, "", "  ")
		if err != nil {
			return "", err
		}
		return string(jsonData), nil
	}

	// Text format
	var output strings.Builder

	cwd, _ := os.Getwd()
	output.WriteString(fmt.Sprintf("————————— [d-env] Project: %s —————————\n", cwd))
	output.WriteString(fmt.Sprintf("📊 Generated at: %s\n\n", time.Now().Format("2006-01-02 15:04:05")))

	for _, result := range results {
		if config.Quiet && result.Error == nil {
			continue
		}

		if result.Display != "" {
			output.WriteString(result.Display + "\n")
		}
	}

	return output.String(), nil
}
