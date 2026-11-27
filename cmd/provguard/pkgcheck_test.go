package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/durgavarapraveen/provguard/internal/config"
	"github.com/durgavarapraveen/provguard/internal/registry"
)

func TestPackageInfoOff(t *testing.T) {
	if packageInfo(config.Config{}, t.TempDir(), "", "npm i x", nil) != nil {
		t.Error("package_check off: want nil")
	}
	on := config.Config{PackageCheck: true}
	for _, cmd := range []string{
		"npm i x --registry https://npm.corp.test",
		"pip install -i https://pypi.corp.test/simple x",
		"pip install --index-url https://pypi.corp.test x",
		"uv add --default-index https://x.test y",
		"npm_config_registry=https://x.test npm i y",
	} {
		if packageInfo(on, t.TempDir(), "", cmd, nil) != nil {
			t.Errorf("%q: custom registry in the command, want nil", cmd)
		}
	}
	if packageInfo(on, t.TempDir(), "", "npm i left-pad", nil) == nil {
		t.Error("plain install: want a lookup")
	}
}

func TestCustomRegistry(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("USERPROFILE", os.Getenv("HOME"))
	t.Setenv("APPDATA", t.TempDir())
	for _, k := range []string{"NPM_CONFIG_REGISTRY", "npm_config_registry", "PIP_INDEX_URL", "UV_INDEX_URL", "CARGO_HOME"} {
		t.Setenv(k, "")
	}
	root := t.TempDir()
	sub := filepath.Join(root, "a", "b")
	os.MkdirAll(sub, 0o700)
	write := func(name, body string) {
		p := filepath.Join(root, name)
		os.MkdirAll(filepath.Dir(p), 0o700)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	dirs := []string{sub, filepath.Dir(sub), root}
	if customRegistryIn(registry.NPM, dirs) || customRegistryIn(registry.PyPI, dirs) || customRegistryIn(registry.Crates, dirs) {
		t.Fatal("no config: want false")
	}
	write(".npmrc", "registry=https://registry.npmjs.org/\n")
	if customRegistryIn(registry.NPM, dirs) {
		t.Error("public registry in .npmrc: want false")
	}
	write(".npmrc", "//registry.npmjs.org/:_authToken=${NPM_TOKEN}\n")
	if customRegistryIn(registry.NPM, dirs) {
		t.Error("npm login token line only: want false")
	}
	write(".npmrc", "@corp:registry=https://npm.corp.test\n")
	if !customRegistryIn(registry.NPM, dirs) {
		t.Error("scoped registry in a parent .npmrc: want true")
	}
	write("pyproject.toml", "[[tool.uv.index]]\nurl = \"https://x.test\"\n")
	if !customRegistryIn(registry.PyPI, dirs) {
		t.Error("uv index: want true")
	}
	if customRegistryIn(registry.Crates, dirs) {
		t.Error("crates: want false")
	}
	write(".cargo/config.toml", "[source.crates-io]\nreplace-with = \"mirror\"\n")
	if !customRegistryIn(registry.Crates, dirs) {
		t.Error("cargo mirror: want true")
	}
	t.Setenv("PIP_INDEX_URL", "https://x.test")
	if !customRegistry(registry.PyPI, t.TempDir()) {
		t.Error("PIP_INDEX_URL: want true")
	}
}

func TestLocalBin(t *testing.T) {
	root := t.TempDir()
	sub := filepath.Join(root, "pkg", "src")
	os.MkdirAll(sub, 0o700)
	os.MkdirAll(filepath.Join(root, "node_modules", ".bin"), 0o700)
	os.WriteFile(filepath.Join(root, "node_modules", ".bin", "my-tool"), nil, 0o600)
	if !localBin(sub, "my-tool") {
		t.Error("bin in a parent node_modules: want true")
	}
	if localBin(sub, "other") {
		t.Error("missing bin: want false")
	}
}
