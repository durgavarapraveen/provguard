package protect

import "github.com/durgavarapraveen/provguard/internal/realpath"

// finalPath resolves links, junctions and Windows path forms of an existing path.
var finalPath = realpath.Final
