package core

import (
	"os"
	"path/filepath"
)

// AgentDir is an agent's folder: the value of the environment variable env
// when it is set, else rel joined to the user's home folder.
func AgentDir(env string, rel ...string) (string, error) {
	if h := os.Getenv(env); h != "" {
		return h, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(append([]string{home}, rel...)...), nil
}

// Exists reports whether the folder dir returns, joined with sub, exists.
// Adapters use it to tell whether their agent is installed.
func Exists(dir func() (string, error), sub ...string) bool {
	d, err := dir()
	if err != nil {
		return false
	}
	_, err = os.Stat(filepath.Join(append([]string{d}, sub...)...))
	return err == nil
}
