package sink

import (
	"bytes"
	"testing"
)

func TestJSONLWritesOneLinePerRecord(t *testing.T) {
	var buf bytes.Buffer
	s := NewJSONL(&buf)
	if err := s.Write("event", map[string]string{"path": "/tmp/<x>&"}); err != nil {
		t.Fatal(err)
	}
	if err := s.Write("alert", 1); err != nil {
		t.Fatal(err)
	}
	want := `{"type":"event","data":{"path":"/tmp/<x>&"}}` + "\n" + `{"type":"alert","data":1}` + "\n"
	if buf.String() != want {
		t.Fatalf("got %q\nwant %q", buf.String(), want)
	}
}
