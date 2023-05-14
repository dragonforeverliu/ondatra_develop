// Copyright 2021 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package stcweb

import (
	"fmt"
	"regexp"

	"golang.org/x/net/context"
)

const resourceManagerPath = "resourceManager"

// xpathFieldsRE matches words immediately after a slash (including the slash).
var xpathFieldsRE = regexp.MustCompile(`/(\w+)`)

// Config represents the IxNetwork config API.
type Config struct {
	sess *Session
}

// Export exports the current full configuration of the IxNetwork session.
func (c *Config) Export(ctx context.Context) (string, error) {
	const exportConfigPath = resourceManagerPath + "/operations/exportconfig"
	exportReqArgs := OpArgs{
		c.sess.AbsPath(resourceManagerPath),
		[]string{"/descendant-or-self::*"},
		false,
		"json",
	}
	var cfg string
	if err := c.sess.Post(ctx, exportConfigPath, exportReqArgs, &cfg); err != nil {
		return "", fmt.Errorf("failed to export IxNetwork config from session: %w", err)
	}
	return cfg, nil
}

// Import imports the specified config into the IxNetwork session.
// If overwrite is 'true', the existing config is completely replaced with the
// specified config; otherwise the config is updated at or below the node
// represented by the specified config. For values that are a list of nodes,
// only the nodes that are specified are updated. (E.g. you cannot remove a
// config node from a list with overwrite set to 'false'.)
func (c *Config) Import(ctx context.Context, cfg string, overwrite bool) error {
	const importConfigPath = resourceManagerPath + "/operations/importconfig"
	importReqData := OpArgs{
		c.sess.AbsPath(resourceManagerPath),
		cfg,
		overwrite,
		"suppressNothing",
		false,
	}
	if err := c.sess.Post(ctx, importConfigPath, importReqData, nil); err != nil {
		return fmt.Errorf("failed import IxNetwork config to session: %w", err)
	}
	return nil
}
