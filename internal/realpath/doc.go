// Package realpath resolves a path to the file the operating system opens.
// On Windows that includes junctions, which filepath.EvalSymlinks does not
// follow. It is shared by self-protection (internal/protect) and labeling
// (internal/label).
package realpath
