package policy

import (
	"path"
	"regexp"
	"sort"
	"strings"
	"sync"

	"github.com/durgavarapraveen/provguard/internal/config"
	"github.com/durgavarapraveen/provguard/internal/shell"
)

// Packs are built-in rule sets that a user or a repository policy turns on
// by name. They ask before changes to shared infrastructure; deletions are
// already covered by the destroy rule.
var Packs = map[string][]config.Rule{
	"terraform": {
		{Name: "apply", Command: "terraform apply", Action: "ask"},
		{Name: "import", Command: "terraform import", Action: "ask"},
		{Name: "state", Command: "terraform state", Action: "ask"},
		{Name: "force-unlock", Command: "terraform force-unlock", Action: "ask"},
		{Name: "tofu-apply", Command: "tofu apply", Action: "ask"},
		{Name: "tofu-state", Command: "tofu state", Action: "ask"},
		{Name: "pulumi-up", Command: "pulumi up", Action: "ask"},
	},
	"kubernetes": {
		{Name: "change", Command: "kubectl apply", Action: "ask"},
		{Name: "create", Command: "kubectl create", Action: "ask"},
		{Name: "replace", Command: "kubectl replace", Action: "ask"},
		{Name: "patch", Command: "kubectl patch", Action: "ask"},
		{Name: "edit", Command: "kubectl edit", Action: "ask"},
		{Name: "scale", Command: "kubectl scale", Action: "ask"},
		{Name: "drain", Command: "kubectl drain", Action: "ask"},
		{Name: "delete", Command: "kubectl delete", Action: "ask"},
		{Name: "helm-install", Command: "helm install", Action: "ask"},
		{Name: "helm-upgrade", Command: "helm upgrade", Action: "ask"},
		{Name: "helm-rollback", Command: "helm rollback", Action: "ask"},
	},
	"aws": {
		{Name: "create", Command: "aws create-*", Action: "ask"},
		{Name: "put", Command: "aws put-*", Action: "ask"},
		{Name: "update", Command: "aws update-*", Action: "ask"},
		{Name: "modify", Command: "aws modify-*", Action: "ask"},
		{Name: "attach", Command: "aws attach-*", Action: "ask"},
		{Name: "run-instances", Command: "aws run-instances", Action: "ask"},
		{Name: "deploy", Command: "aws deploy", Action: "ask"},
	},
	"gcloud": {
		{Name: "create", Command: "gcloud create", Action: "ask"},
		{Name: "update", Command: "gcloud update", Action: "ask"},
		{Name: "deploy", Command: "gcloud deploy", Action: "ask"},
		{Name: "iam", Command: "gcloud add-iam-policy-binding", Action: "ask"},
		{Name: "set-iam", Command: "gcloud set-iam-policy", Action: "ask"},
	},
	"azure": {
		{Name: "create", Command: "az create", Action: "ask"},
		{Name: "update", Command: "az update", Action: "ask"},
		{Name: "set", Command: "az set", Action: "ask"},
	},
}

// PackNames lists the built-in packs.
func PackNames() []string {
	var out []string
	for n := range Packs {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// matchRules returns the first rule, of the user's, the repository's and
// the packs', that matches the call: user and repository rules first, in
// their order, then packs.
func matchRules(in Input) (config.Rule, string, bool) {
	for _, r := range in.Config.Rules {
		if ruleMatches(r, in) {
			return r, "rule:" + r.Name, true
		}
	}
	for _, p := range in.Config.Packs {
		p = strings.ToLower(strings.TrimSpace(p))
		for _, r := range Packs[p] {
			if ruleMatches(r, in) {
				return r, "pack:" + p + "/" + r.Name, true
			}
		}
	}
	return config.Rule{}, "", false
}

// ruleMatches reports whether every part the rule sets matches the call.
// Command and Match rules apply only to shell commands.
func ruleMatches(r config.Rule, in Input) bool {
	if r.Tool != "" {
		if ok, _ := path.Match(strings.ToLower(r.Tool), strings.ToLower(in.Tool)); !ok {
			return false
		}
	} else if len(in.Cmds) == 0 {
		return false
	}
	if r.Command != "" && !commandMatches(strings.Fields(strings.ToLower(r.Command)), in.Cmds) {
		return false
	}
	if r.Match != "" {
		re := compiled(r.Match)
		if re == nil || len(in.Cmds) == 0 || !re.MatchString(in.Text) {
			return false
		}
	}
	return true
}

// commandMatches: some command's name matches words[0], and its other
// arguments that are not flags contain words[1:] in order.
func commandMatches(words []string, cmds []shell.Cmd) bool {
	if len(words) == 0 {
		return true
	}
	for _, c := range cmds {
		if c.Dynamic || !glob(words[0], c.Name) {
			continue
		}
		rest := words[1:]
		for _, a := range c.Args[min(1, len(c.Args)):] {
			if len(rest) == 0 {
				break
			}
			if a = strings.ToLower(a); !strings.HasPrefix(a, "-") && glob(rest[0], a) {
				rest = rest[1:]
			}
		}
		if len(rest) == 0 {
			return true
		}
	}
	return false
}

func glob(pattern, s string) bool {
	ok, _ := path.Match(pattern, s)
	return ok
}

// regexps caches compiled Match patterns; rules were validated on load.
var regexps sync.Map

func compiled(expr string) *regexp.Regexp {
	if v, ok := regexps.Load(expr); ok {
		return v.(*regexp.Regexp)
	}
	re, err := regexp.Compile(expr)
	if err != nil {
		return nil
	}
	regexps.Store(expr, re)
	return re
}
