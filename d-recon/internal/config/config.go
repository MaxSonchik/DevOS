package config

import (
	"d-recon/internal/core"
	"log"

	"github.com/spf13/viper"
)

func LoadConfig() *core.Config {
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath(".")
	viper.AddConfigPath("./config")

	// Default values
	viper.SetDefault("profile", "quick")
	viper.SetDefault("output_format", "text")
	viper.SetDefault("output_dir", "results")
	viper.SetDefault("rate_limit", 10)
	viper.SetDefault("timeout", 300)
	viper.SetDefault("verbose", false)
	viper.SetDefault("modules", []string{"subdomains", "ports", "web"})

	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			log.Println("Config file not found, using defaults")
		} else {
			log.Fatalf("Error reading config: %v", err)
		}
	}

	var config core.Config
	if err := viper.Unmarshal(&config); err != nil {
		log.Fatalf("Unable to decode config: %v", err)
	}

	return &config
}
