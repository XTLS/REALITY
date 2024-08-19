// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE-Go file.

//go:build !boringcrypto

package reality

func needFIPS() bool { return false }
