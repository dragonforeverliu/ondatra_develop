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
	"encoding/json"
	"fmt"
	"path"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/net/context"

	log "github.com/golang/glog"
)

const (
	sessionsPath = "/ondatra/v1/sessions"
)

func sessionPath(id int) string {
	return path.Join(sessionsPath, strconv.Itoa(id))
}

var (
	sessionDisallowRE = regexp.MustCompile(`[<>:"/\|?*]`)
)

// StcAgent represents the StcAgent application on Ixia Web Platform.
type StcAgent struct {
	stcWeb *StcWeb
}

// NewSession creates a new StcAgent session with the specified name.
func (n *StcAgent) NewSession(ctx context.Context, sessionname string) (*Session, error) {

	in := struct {
		Userid       string `json:"userid"`
		Password     string `json:"password"`
		Sessionname  string `json:"sessionname"`
		StartTimeout int    `json:"start_timeout"`
	}{
		Userid:       n.stcWeb.cfg.username,
		Password:     n.stcWeb.cfg.password,
		Sessionname:  sessionname,
		StartTimeout: 2000,
	}
	out := struct {
		Session_id   string `json:"session_id"`
		Session_name string `json:"session_name"`
		User_id      string `json:"user_id"`
		Process_id   int    `json:"process_id"`
	}{}

	if err := n.stcWeb.jsonReq(ctx, post, sessionsPath, in, &out); err != nil {
		return nil, fmt.Errorf("error creating session: %w", err)
	}

	log.Info("Create session ....out=", out)

	n.stcWeb.apiSessionId = out.Session_id

	return &Session{stcWeb: n.stcWeb,
		id:         out.Process_id,
		user_id:    out.User_id,
		session_id: out.Session_id,
		name:       out.Session_name}, nil
}

type sessionData struct {
	ID   int    `json:"id"`
	Name string `json:"sessionName"`
}

// encodeSessionName encodes the given session name into an allowed format.
func encodeSessionName(s string) string {
	const ellipses = "..."
	s = sessionDisallowRE.ReplaceAllLiteralString(s, "_")
	if maxLen := 64; len(s) > maxLen {
		s = s[:maxLen-len(ellipses)] + ellipses
	}
	return s
}

// FetchSession fetches the StcAgent session with the specified ID.
func (n *StcAgent) FetchSession(ctx context.Context, id int) (*Session, error) {
	data := sessionData{}
	if err := n.stcWeb.jsonReq(ctx, get, sessionPath(id), nil, &data); err != nil {
		return nil, fmt.Errorf("error fetching session: %w", err)
	}
	return &Session{stcWeb: n.stcWeb, id: id, name: data.Name}, nil
}

// FetchSessions fetches all current StcAgent sessions.
func (n *StcAgent) FetchSessions(ctx context.Context) (map[int]*Session, error) {
	var data []*sessionData
	if err := n.stcWeb.jsonReq(ctx, get, sessionsPath, nil, &data); err != nil {
		return nil, fmt.Errorf("error fetching sessions: %w", err)
	}
	idToSession := map[int]*Session{}
	for _, s := range data {
		idToSession[s.ID] = &Session{stcWeb: n.stcWeb, id: s.ID, name: s.Name}
	}
	return idToSession, nil
}

// DeleteSession deletes the StcAgent session with the specified ID.
// This is a noop if the session is already deleted.
func (n *StcAgent) DeleteSession(ctx context.Context, id int) error {
	spath := sessionPath(id)
	stopErr := n.stcWeb.jsonReq(ctx, post, path.Join(spath, "operations/stop"), nil, nil)
	// A 404 error on stop indicates the session was already deleted.
	if stopErr != nil {
		if strings.Contains(stopErr.Error(), "404") {
			return nil
		}
		log.Warningf("Error stopping session, which may be due to another stop in progress: %v"+
			"\nWill still attempt to delete the session.", stopErr)
	}
	if err := n.stcWeb.jsonReq(ctx, delete, spath, nil, nil); err != nil {
		if stopErr != nil {
			return fmt.Errorf("error deleting session after error stopping session: %w, %v", err, stopErr)
		}
		return fmt.Errorf("error deleting session: %w", err)
	}
	return nil
}

// Session represents an StcAgent session.
type Session struct {
	stcWeb     *StcWeb
	id         int    // the ID of a session_id
	name       string // session_name got from stcagent
	user_id    string // is the username from the .binding file.
	session_id string // formate: session_name - user_id

	// StcAgent doesn't like concurrent HTTP requests to the same session.
	// Use mutex to prevent concurrency.
	mu sync.Mutex
}

// ID returns the unique ID of the session.
func (s *Session) ID() int {
	return s.id
}

// Name returns the descriptive name of the session.
func (s *Session) Name() string {
	return s.name
}

func (s *Session) String() string {
	return fmt.Sprintf("Session %d %s", s.id, s.name)
}

// AbsPath returns an absolute path, given a path relative to the StcAgent session.
// If relPath is already an absolute path, this method returns the input string.
func (s *Session) AbsPath(relPath string) string {
	absPrefix := sessionPath(s.id)
	if strings.HasPrefix(relPath, absPrefix) {
		return relPath
	}
	return path.Join(absPrefix, relPath)
}

// Get submits a JSON GET request, at a path relative to the StcAgent session.
func (s *Session) Get(ctx context.Context, path string, out any) error {
	return s.jsonReq(ctx, get, path, nil, out)
}

// Delete submits a JSON DELETE request, at a path relative to the StcAgent session.
func (s *Session) Delete(ctx context.Context, path string) error {
	// Content-type (JSON or binary) does not matter for a DELETE.
	return s.jsonReq(ctx, delete, path, nil, nil)
}

// Patch submits a JSON PATCH request, at a path relative to the StcAgent session.
func (s *Session) Patch(ctx context.Context, path string, in any) error {
	return s.jsonReq(ctx, patch, path, in, nil)
}

// Post submits a JSON POST request, at a path relative to the StcAgent session.
func (s *Session) Post(ctx context.Context, path string, in, out any) error {
	return s.jsonReq(ctx, post, path, in, out)
}

// Config returns the config API for this session.
func (s *Session) Config() *Config {
	return &Config{sess: s}
}

// Error represents an error reported by an StcAgent session.
type Error struct {
	ID                  int      `json:"id"`
	Level               string   `json:"errorLevel"`
	Code                int      `json:"errorCode"`
	Description         string   `json:"description"`
	Name                string   `json:"name"`
	LastModified        string   `json:"lastModified"`
	Provider            string   `json:"provider"`
	InstanceColumnNames []string `json:"sourceColumnsDisplayName"`
	InstanceRowValues   []map[string]string
}

func (s *Session) jsonReq(ctx context.Context, method httpMethod, path string, in, out any) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.stcWeb.jsonReq(ctx, method, s.AbsPath(path), in, out)
}

func (s *Session) binaryReq(ctx context.Context, method httpMethod, path string, content []byte) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.stcWeb.binaryReq(ctx, method, s.AbsPath(path), content)
}

// OpArgs is a list of arguments for an operation to use as input to a POST request.
type OpArgs []any

// MarshalJSON marshals the operation arguments to JSON.
func (a OpArgs) MarshalJSON() ([]byte, error) {
	m := make(map[string]any)
	for i, v := range a {
		m["arg"+strconv.Itoa(i+1)] = v
	}
	return json.Marshal(m)
}
