// Package aa decodes Apple Archive (.aar) containers and the "pbz*" compression
// stream Apple wraps them in.
//
// An archive is a flat sequence of items, each a header followed by the blobs
// that header declares (file data, extended attributes, ...). See archive.go for
// the field encoding and stream.go for the outer stream. Extraction streams: a
// 10 GB archive is unpacked with bounded memory.
package aa
