// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !amd64

package perf

func rdpmc(counter uint32) int64 {
	panic("unreachable")
}
