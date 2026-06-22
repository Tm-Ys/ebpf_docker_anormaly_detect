// Package container resolves host PIDs to their owning Docker container
// using /proc/<pid>/cgroup + the Docker Engine API over the unix socket.
package container

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"
)

// DefaultDockerSocket is where dockerd listens on most hosts.
const DefaultDockerSocket = "/var/run/docker.sock"

// DockerClient talks to the Docker Engine API over the local unix socket.
// No third-party dependency: just net/http + a custom dialer.
type DockerClient struct {
	socket  string
	client  *http.Client
	version string
}

// NewDockerClient returns a client bound to the given socket path.
func NewDockerClient(socket string) *DockerClient {
	dialer := &net.Dialer{Timeout: 2 * time.Second}
_transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, "unix", socket)
		},
	}
	return &DockerClient{
		socket:  socket,
		version: "v1.24", // oldest API we target; works on all modern dockerd
		client:  &http.Client{Transport: _transport, Timeout: 5 * time.Second},
	}
}

// ContainerSummary mirrors the subset of /containers/json we care about.
type ContainerSummary struct {
	ID    string   `json:"Id"`
	Names []string `json:"Names"`
	Image string   `json:"Image"`
	Labels map[string]string `json:"Labels"`
}

// ContainerDetail mirrors the subset of /containers/{id}/json we care about.
type ContainerDetail struct {
	ID      string         `json:"Id"`
	Name    string         `json:"Name"`
	Image   string         `json:"Image"`
	State   ContainerState `json:"State"`
	Created string         `json:"Created"` // ISO 8601 timestamp
}

type ContainerState struct {
	Status     string `json:"Status"`     // running / exited / ...
	Running    bool   `json:"Running"`
	Pid        int    `json:"Pid"`
	StartedAt  string `json:"StartedAt"`
	ExitCode   int    `json:"ExitCode"`
	Error      string `json:"Error"`
}

func (c *DockerClient) get(ctx context.Context, path string, out interface{}) error {
	url := fmt.Sprintf("http://localhost/%s%s", c.version, path)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("docker api %s: %s: %s", path, resp.Status, string(body))
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

// ListContainers returns all containers (running + stopped) the daemon knows.
func (c *DockerClient) ListContainers(ctx context.Context) ([]ContainerSummary, error) {
	var out []ContainerSummary
	if err := c.get(ctx, "/containers/json?all=true", &out); err != nil {
		return nil, err
	}
	return out, nil
}

// InspectContainer returns detailed info about one container.
func (c *DockerClient) InspectContainer(ctx context.Context, id string) (*ContainerDetail, error) {
	var out ContainerDetail
	if err := c.get(ctx, "/containers/"+id+"/json", &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Ping checks the daemon is reachable.
func (c *DockerClient) Ping(ctx context.Context) error {
	var v map[string]interface{}
	if err := c.get(ctx, "/version", &v); err != nil {
		return err
	}
	if _, ok := v["Version"]; !ok {
		return errors.New("docker: malformed version response")
	}
	return nil
}
