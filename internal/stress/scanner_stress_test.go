//go:build stress

package stress

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/DAVANO-INNOVATION-LAB/cupel/internal/inspector"
)

// Inputs designed to make a parser do something other than parse.
//
// Every one of these is a file a registry would happily serve. The scanner
// reads whatever it is pointed at, so the only acceptable outcome for any of
// them is a finding or a clean refusal — never a panic, never a hang, never
// an allocation the size of the header claims.
func TestHostileHeadersDoNotTakeTheScannerDown(t *testing.T) {
	cases := []struct {
		name string
		file string
		data []byte
	}{
		{
			"safetensors header claims 2^63 bytes",
			"model.safetensors",
			append(le64(math.MaxInt64), []byte(`{"a":{}}`)...),
		},
		{
			"safetensors header claims more than the file holds",
			"model.safetensors",
			append(le64(1<<40), []byte(`{"a":{}}`)...),
		},
		{
			"safetensors header length of zero",
			"model.safetensors",
			append(le64(0), []byte(`{}`)...),
		},
		{
			"safetensors truncated mid-header",
			"model.safetensors",
			append(le64(1024), []byte(`{"a":{"dtype":"F3`)...),
		},
		{
			"safetensors header is one byte short of the length prefix",
			"model.safetensors",
			[]byte{1, 2, 3, 4, 5, 6, 7},
		},
		{
			"gguf with an absurd tensor count",
			"model.gguf",
			ggufHeader(math.MaxUint64, 4),
		},
		{
			"gguf with an absurd kv count",
			"model.gguf",
			ggufHeader(4, math.MaxUint64),
		},
		{
			"gguf truncated after the magic",
			"model.gguf",
			[]byte("GGUF"),
		},
		{
			"onnx that is only a field header promising a huge payload",
			"model.onnx",
			[]byte{0x0a, 0xff, 0xff, 0xff, 0xff, 0x0f},
		},
		{
			"npy with a header longer than the file",
			"weights.npy",
			append([]byte("\x93NUMPY\x01\x00\xff\xff"), []byte("{'descr'")...),
		},
		{
			"json config nested a thousand deep",
			"config.json",
			[]byte(strings.Repeat(`{"a":`, 1000) + "1" + strings.Repeat("}", 1000)),
		},
		{
			"a file that is all null bytes",
			"model.safetensors",
			make([]byte, 1<<20),
		},
		{
			"a file that is one very long line",
			"config.json",
			append([]byte(`{"x":"`), append(bytes.Repeat([]byte("A"), 4<<20), []byte(`"}`)...)...),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, tc.file), tc.data, 0o644); err != nil {
				t.Fatal(err)
			}

			done := make(chan struct{})
			var findings int
			var perr any
			go func() {
				defer func() {
					perr = recover()
					close(done)
				}()
				rep, err := inspector.Inspect(dir, inspector.DefaultLimits())
				if err == nil {
					findings = len(rep.Findings)
				}
			}()

			select {
			case <-done:
			case <-time.After(30 * time.Second):
				t.Fatalf("the scanner did not finish in 30s: a hostile header hangs it")
			}
			if perr != nil {
				t.Fatalf("the scanner panicked: %v", perr)
			}
			t.Logf("handled, %d findings", findings)
		})
	}
}

func le64(v uint64) []byte {
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, v)
	return b
}

func ggufHeader(tensors, kv uint64) []byte {
	b := []byte("GGUF")
	b = binary.LittleEndian.AppendUint32(b, 3)
	b = binary.LittleEndian.AppendUint64(b, tensors)
	b = binary.LittleEndian.AppendUint64(b, kv)
	return b
}

// Throughput on ordinary models, so a regression in scan cost is visible.
func TestScannerThroughputOnOrdinaryModels(t *testing.T) {
	root := t.TempDir()
	const models = 300

	for i := 0; i < models; i++ {
		dir := filepath.Join(root, fmt.Sprintf("m%03d", i))
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		header, _ := json.Marshal(map[string]any{
			"weight": map[string]any{"dtype": "F32", "shape": []int{256, 256}, "data_offsets": []int{0, 262144}},
		})
		body := append(le64(uint64(len(header))), header...)
		body = append(body, make([]byte, 262144)...)
		os.WriteFile(filepath.Join(dir, "model.safetensors"), body, 0o644)
		os.WriteFile(filepath.Join(dir, "config.json"),
			[]byte(`{"model_type":"llama","architectures":["LlamaForCausalLM"]}`), 0o644)
	}

	start := time.Now()
	total := 0
	for i := 0; i < models; i++ {
		rep, err := inspector.Inspect(filepath.Join(root, fmt.Sprintf("m%03d", i)), inspector.DefaultLimits())
		if err != nil {
			t.Fatalf("model %d: %v", i, err)
		}
		total += len(rep.Findings)
	}
	elapsed := time.Since(start)
	t.Logf("%d models in %s (%.1f/s), %d findings total",
		models, elapsed.Round(time.Millisecond), float64(models)/elapsed.Seconds(), total)

	if total != 0 {
		t.Errorf("%d findings on clean models: false positives at scale", total)
	}
}
