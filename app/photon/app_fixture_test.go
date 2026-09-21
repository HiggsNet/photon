package main

import "time"

// testApp keeps fixture configuration and a mutable test clock together.
// Production functions receive only the explicit inputs they need.
type testApp struct {
	Config *appConfig
	Clock  func() time.Time
	Direct bool
}

func testConfigWithStatePath(config *appConfig, path string) *appConfig {
	if config == nil {
		config = defaultAppConfig()
	}
	copyConfig := *config
	copyConfig.StatePath = path
	return &copyConfig
}

func (app *testApp) Now() time.Time {
	if app != nil && app.Clock != nil {
		return app.Clock()
	}
	return time.Now()
}
