package shell

import (
	"slices"
	"testing"
)

// Package targets must hold only package names: the dependency gate looks
// each one up, and a folder or tag taken for a name is a false alarm.
func TestPackageTargets(t *testing.T) {
	cases := []struct{ cmd, want string }{
		{`npm install left-pad`, "EXEC_REMOTE:package_install:npm->left-pad"},
		{`npm --prefix web install react`, "EXEC_REMOTE:package_install:npm->react"},
		{`npm i -w app --tag beta lodash`, "EXEC_REMOTE:package_install:npm->lodash"},
		{`pnpm -C web add zod`, "EXEC_REMOTE:package_install:pnpm->zod"},
		{`pnpm add -w zod`, "EXEC_REMOTE:package_install:pnpm->zod"},
		{`npm ci`, "EXEC_REMOTE:package_install:npm"},
		{`npx create-vite@latest my-app`, "EXEC_REMOTE:run_remote_package:npx->create-vite@latest"},
		{`npx -p typescript tsc --init`, "EXEC_REMOTE:run_remote_package:npx->typescript"},
		{`npx --package=cowsay cowsay hi`, "EXEC_REMOTE:run_remote_package:npx->cowsay"},
		{`npx -c 'echo hi'`, "EXEC_REMOTE:run_remote_package:npx"},
		{`npm exec -- eslint .`, "EXEC_REMOTE:run_remote_package:npm->eslint"},
		{`pnpm dlx degit user/repo`, "EXEC_REMOTE:run_remote_package:pnpm->degit"},
		{`uvx ruff check`, "EXEC_REMOTE:run_remote_package:uvx->ruff"},
		{`uvx -p 3.12 --from httpie http x.test`, "EXEC_REMOTE:run_remote_package:uvx->httpie"},
		{`pipx run cowsay hello`, "EXEC_REMOTE:run_remote_package:pipx->cowsay"},
		{`pip install --target lib --index-url https://x.test requests`, "EXEC_REMOTE:package_install:pip->requests"},
		{`uv add --group dev pytest`, "EXEC_REMOTE:package_install:uv->pytest"},
		{`cargo install ripgrep`, "EXEC_REMOTE:package_install:cargo->ripgrep"},
		{`cargo install --root ~/bin --version 14 ripgrep`, "EXEC_REMOTE:package_install:cargo->ripgrep"},
		{`cargo add serde -F derive`, "EXEC_REMOTE:package_install:cargo->serde"},
		{`cargo add -p core tokio`, "EXEC_REMOTE:package_install:cargo->tokio"},
	}
	for _, c := range cases {
		got := Analyze(c.cmd, Bash).SinkStrings()
		if !slices.Contains(got, c.want) {
			t.Errorf("%q: want %q in %v", c.cmd, c.want, got)
		}
	}
}
