package shell

import (
	"regexp"
	"strings"
)

// destructive adds a DESTROY sink for commands that delete data outside the
// project and cannot be undone from it: infrastructure, clusters, cloud
// resources, container volumes, databases and disks. The policy asks before
// these in every session (rule 5), not only after untrusted input.
//
// Routine work stays quiet: deleting a pod, removing a container or running
// `terraform plan` adds nothing.
func destructive(a *Analysis, name string, args, pos []string) {
	at := func(i int) string {
		if i < len(pos) {
			return strings.ToLower(pos[i])
		}
		return ""
	}
	if hasFlag(args, 0, "--help", "-help") {
		return
	}
	target := strings.Join(pos, " ")
	switch name {
	case "terraform", "tofu", "terragrunt":
		if at(0) == "destroy" || at(0) == "apply" && hasFlag(args, 0, "-destroy", "--destroy") {
			a.sink(Destroy, name+"_destroy", target)
		}
	case "pulumi":
		if at(0) == "destroy" || at(0) == "stack" && at(1) == "rm" {
			a.sink(Destroy, "pulumi_destroy", target)
		}
	case "kubectl", "oc":
		// Global flags may come first (kubectl -n prod delete ns x).
		for i := range pos {
			if at(i) == "delete" && (clusterWide[strings.Split(at(i+1), "/")[0]] || hasFlag(args, 'A', "--all", "--all-namespaces")) {
				a.sink(Destroy, name+"_delete", target)
				break
			}
		}
	case "helm":
		for i := range pos {
			if v := at(i); v == "uninstall" || v == "delete" || v == "del" || v == "un" {
				a.sink(Destroy, "helm_uninstall", target)
				break
			}
		}
	case "docker", "podman":
		switch {
		case at(0) == "system" && at(1) == "prune",
			at(0) == "volume" && (at(1) == "rm" || at(1) == "remove" || at(1) == "prune"),
			at(0) == "compose" && at(1) == "down" && hasFlag(args, 'v', "--volumes"):
			a.sink(Destroy, name+"_"+at(0)+"_"+at(1), target)
		}
	case "aws":
		for _, p := range pos {
			lp := strings.ToLower(p)
			if strings.HasPrefix(lp, "delete-") || strings.HasPrefix(lp, "terminate-") {
				a.sink(Destroy, "cloud_delete:aws", target)
				return
			}
		}
		if at(0) == "s3" && (at(1) == "rb" || at(1) == "rm" && hasFlag(args, 0, "--recursive")) {
			a.sink(Destroy, "cloud_delete:aws", target)
		}
	case "gcloud", "az":
		for _, p := range pos {
			if lp := strings.ToLower(p); lp == "delete" || lp == "rm" && hasFlag(args, 'r', "--recursive") {
				a.sink(Destroy, "cloud_delete:"+name, target)
				return
			}
		}
	case "gsutil":
		if at(0) == "rb" || at(0) == "rm" && hasFlag(args, 'r', "--recursive") {
			a.sink(Destroy, "cloud_delete:gsutil", target)
		}
	case "dropdb":
		a.sink(Destroy, "db_drop:dropdb", target)
	case "mysqladmin":
		if at(0) == "drop" {
			a.sink(Destroy, "db_drop:mysqladmin", target)
		}
	case "dd":
		for _, x := range args {
			if v, ok := strings.CutPrefix(x, "of="); ok && strings.HasPrefix(v, "/dev/") && v != "/dev/null" {
				a.sink(Destroy, "dd_device", v)
			}
		}
	case "format-volume", "clear-disk", "initialize-disk":
		a.sink(Destroy, name, target)
	default:
		if dbClients[name] {
			if m := destructiveSQL.FindString(strings.Join(args, " ")); m != "" {
				a.sink(Destroy, "db_drop:"+name, m)
			}
		}
	}
}

// clusterWide: kubectl resources whose deletion loses data or a whole
// environment, not a pod or a deployment that is recreated from a manifest.
var clusterWide = set("namespace", "namespaces", "ns", "pv", "persistentvolume", "persistentvolumes",
	"pvc", "persistentvolumeclaim", "persistentvolumeclaims", "crd", "crds",
	"customresourcedefinition", "customresourcedefinitions", "node", "nodes", "all")

// dbClients run SQL or database commands given on the command line.
var dbClients = set("psql", "mysql", "mariadb", "sqlite3", "sqlcmd", "mongosh", "mongo",
	"redis-cli", "cockroach", "clickhouse-client", "clickhouse", "duckdb")

// destructiveSQL: statements that drop or empty a database object. A DELETE
// without WHERE empties the table; one with WHERE is normal work.
var destructiveSQL = regexp.MustCompile(`(?i)\b(?:drop\s+(?:table|database|schema|view|collection|keyspace)\b|truncate\s+(?:table\s+)?[\w."` + "`" + `]+|delete\s+from\s+[\w."` + "`" + `]+\s*(?:;|"|'|$)|flushall\b|flushdb\b|\.dropdatabase\s*\(|\.drop\s*\(\s*\))`)
