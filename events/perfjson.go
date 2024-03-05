// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build linux

package events

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"regexp"
	"strings"
	"sync"
)

// TODO: It might just be better to use the perfmon database. See
// event_download.py in github.com/andikleen/pmu-tools for downloading it all as
// JSON and
// https://github.com/torvalds/linux/blob/master/tools/perf/pmu-events/jevents.py
// for the tool that converts the JSON into perf C definitions. Alternatively,
// https://github.com/andikleen/pmu-tools/blob/master/jevents/jevents.c is a C
// implementation that translates from the JSON definitions directly to
// perf_event_attrs.

func resolvePerfJsonEvent(pmu *pmuDesc, eventName string) (pmuEvent, error) {
	list, err := getPerfList()
	if err != nil {
		return pmuEvent{}, err
	}
	evJSON, ok := list[eventName]
	if !ok {
		return pmuEvent{}, errUnknownEvent
	}

	// Got the event. Make sure we can actually use it.
	if evJSON.Encoding == "" {
		return pmuEvent{}, fmt.Errorf("unsupported event %q: no encoding from perf list -j", eventName)
	}
	return evJSON.toPMUEvent()
}

type perfJson struct {
	Unit              string
	Topic             string
	EventName         string
	ScaleUnit         string
	EventAlias        string
	EventType         string
	BriefDescription  string
	PublicDescription string
	Encoding          string

	// TODO: We don't support metrics yet. They have an empty EventName.
}

var perfErrRe = regexp.MustCompile(`\}Error: .*`)

var perfListHook func(outBuf io.Writer)

var getPerfList = sync.OnceValues(func() (map[string]perfJson, error) {
	var outBuf bytes.Buffer
	var errBuf bytes.Buffer
	var err error
	if perfListHook != nil {
		perfListHook(&outBuf)
	} else {
		cmd := exec.Command("perf", "list", "-j")
		cmd.Stdout = &outBuf
		cmd.Stderr = &errBuf
		err = cmd.Run()
	}
	return parsePerfList(outBuf.Bytes(), errBuf.Bytes(), err)
})

func parsePerfList(data, errOut []byte, err error) (map[string]perfJson, error) {
	if err != nil {
		if errors.Is(err, exec.ErrNotFound) {
			return nil, fmt.Errorf("perf command not found; cannot enumerate extended events")
		}
		if len(errOut) != 0 {
			out := string(errOut)
			if strings.Contains(out, "Error: unknown switch `j'") {
				// JSON support was added in linux-kernel commit
				// 6ed249441a7d3ead8e81cc926e68d5e7ae031032
				return nil, fmt.Errorf("perf version must be >= 6.2; cannot enumerate extended events")
			}
			return nil, fmt.Errorf("perf list -j failed:\n%s", strings.TrimSpace(out))
		}
		return nil, fmt.Errorf("perf list -j failed: %w", err)
	}

	// Parse output. There's a bug in perf (as of 6.5.13) where it may write
	// errors to stdout interleaved with the JSON. Strip those out.
	data = perfErrRe.ReplaceAllLiteral(data, []byte(`}`))
	var list []perfJson
	if err := json.Unmarshal(data, &list); err != nil {
		return nil, fmt.Errorf("error decoding perf list -j output: %w", err)
	}

	// Construct map from event name to description
	m := make(map[string]perfJson)
	for _, ev := range list {
		if ev.EventName != "" {
			m[ev.EventName] = ev
		}
		if ev.EventAlias != "" {
			m[ev.EventAlias] = ev
		}
	}
	return m, nil
}

// toPMUEvent converts j into a pmuEvent.
func (j perfJson) toPMUEvent() (pmuEvent, error) {
	pmu, params, err := parsePMUEvent(j.Encoding)
	if err == nil && pmu != "cpu" {
		err = fmt.Errorf("expected PMU %q", "cpu")
	}
	if err != nil {
		return pmuEvent{}, fmt.Errorf("unexpected encoding %q from perf list -j: %w", j.Encoding, err)
	}
	scale := 1.0
	unit := ""
	if j.ScaleUnit != "" {
		n, err := fmt.Sscanf(j.ScaleUnit, "%g%s", &scale, &unit)
		if n == 1 && err == io.EOF {
			// This just means the unit was empty. That's fine.
			err = nil
		}
		if err != nil {
			return pmuEvent{}, fmt.Errorf("unexpected ScaleUnit %q from perf list -j: %w", j.ScaleUnit, err)
		}
	}
	return pmuEvent{j.EventName, params, scale, unit}, nil
}