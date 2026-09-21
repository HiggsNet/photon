package main

import (
	"os"
	"time"
)

type AppContext struct {
	Config         *appConfig
	StatePath      string
	Clock          func() time.Time
	DisableControl bool
}

func NewAppContext() (*AppContext, error) {
	config, err := loadAppConfig()
	if err != nil {
		return nil, err
	}
	path := config.StatePath
	if override := os.Getenv("PHOTON_STATE"); override != "" {
		path = override
	}
	return &AppContext{
		Config:    config,
		StatePath: path,
		Clock:     time.Now,
	}, nil
}

func (rt *AppContext) Now() time.Time {
	if rt != nil && rt.Clock != nil {
		return rt.Clock()
	}
	return time.Now()
}
