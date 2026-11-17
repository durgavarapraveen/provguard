package core

import "strings"

// PatchTool is the file-editing tool of Codex and Devin. Its input holds a
// patch in the "*** Begin Patch" format.
const PatchTool = "apply_patch"

// PatchFiles lists the files a patch adds, updates, deletes or moves to
// ("*** Add File: p", "*** Update File: p", "*** Delete File: p",
// "*** Move to: p").
func PatchFiles(patch string) []string {
	var out []string
	for _, line := range strings.Split(patch, "\n") {
		line = strings.TrimSpace(line)
		for _, prefix := range []string{"*** Add File:", "*** Update File:", "*** Delete File:", "*** Move to:"} {
			if p, ok := strings.CutPrefix(line, prefix); ok {
				if p = strings.TrimSpace(p); p != "" {
					out = append(out, p)
				}
			}
		}
	}
	return out
}

// AddPatchPaths lists the files of the patch in input[patchKey] under
// input["path"], where the file checks read them.
func AddPatchPaths(input map[string]any, patchKey string) {
	patch, _ := input[patchKey].(string)
	if patch == "" {
		return
	}
	files := PatchFiles(patch)
	paths := make([]any, len(files))
	for i, f := range files {
		paths[i] = f
	}
	input["path"] = paths
}
