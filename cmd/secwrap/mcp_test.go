package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestMCP(t *testing.T) {
	sdir, hist := t.TempDir(), t.TempDir()
	t.Setenv("SECWRAP_SESSIONS", sdir)
	id := "20260101-120000-curl"
	os.MkdirAll(filepath.Join(sdir, id, "asks"), 0o755)
	ended := time.Now()
	info, _ := json.Marshal(sessionInfo{ID: id, Target: "curl x", Started: ended.Add(-time.Minute), Ended: &ended, History: hist})
	os.WriteFile(filepath.Join(sdir, id, "session.json"), info, 0o644)
	os.WriteFile(filepath.Join(sdir, id, "asks", "1.json"), []byte(`{"id":1,"comm":"curl","kind":"open","path":"/home/me/.ssh/id_ed25519","status":"denied"}`), 0o644)
	os.WriteFile(filepath.Join(hist, "events.jsonl"), []byte(strings.Join([]string{
		`{"time":"2026-01-01T12:00:01Z","comm":"curl","kind":"connect","remote":"93.184.215.14:443"}`,
		`{"time":"2026-01-01T12:00:02Z","comm":"curl","kind":"open","path":"/etc/hosts"}`,
		`{"time":"2026-01-01T12:00:03Z","comm":"curl","kind":"open","path":"/home/me/.ssh/id_ed25519","inScope":true,"blocked":true}`,
		`{"time":"2026-01-01T12:00:04Z","comm":"sh","kind":"open","pa`, // cut short
	}, "\n")), 0o644)
	os.WriteFile(filepath.Join(hist, "report.json"), []byte(`{"target":"curl x"}`), 0o644)

	in := strings.Join([]string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`,
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"list_sessions","arguments":{}}}`,
		`{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"query_events","arguments":{"session":"curl","kind":"open"}}}`,
		`{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"query_events","arguments":{"session":"1","blocked":true}}}`,
		`{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"query_events","arguments":{"session":"1","limit":1}}}`,
		`{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"get_session","arguments":{"session":"curl"}}}`,
		`{"jsonrpc":"2.0","id":8,"method":"tools/call","params":{"name":"list_questions","arguments":{"session":"curl","status":"denied"}}}`,
		`{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"get_session","arguments":{"session":"nope"}}}`,
		`{"jsonrpc":"2.0","id":10,"method":"bogus"}`,
	}, "\n")
	var out bytes.Buffer
	if err := serveMCP(strings.NewReader(in), &out); err != nil {
		t.Fatal(err)
	}
	type resp struct {
		ID     int `json:"id"`
		Result struct {
			Tools   []struct{ Name string } `json:"tools"`
			Content []struct{ Text string } `json:"content"`
			IsError bool                    `json:"isError"`
		} `json:"result"`
		Error *rpcError `json:"error"`
	}
	got := map[int]resp{}
	dec := json.NewDecoder(&out)
	for dec.More() {
		var r resp
		if err := dec.Decode(&r); err != nil {
			t.Fatal(err)
		}
		got[r.ID] = r
	}
	if len(got) != 10 {
		t.Fatalf("want 10 replies (none to the notification), got %d", len(got))
	}
	if n := len(got[2].Result.Tools); n != 4 {
		t.Errorf("tools/list: %d tools", n)
	}
	text := func(id int) string {
		r := got[id]
		if len(r.Result.Content) == 0 {
			t.Fatalf("reply %d: no content (%+v)", id, r)
		}
		return r.Result.Content[0].Text
	}
	var q struct {
		Matched, Returned int
		NextOffset        *int
	}
	for id, want := range map[int][3]int{4: {2, 2, -1}, 5: {1, 1, -1}, 6: {3, 1, 1}} {
		q.NextOffset = nil
		json.Unmarshal([]byte(text(id)), &q)
		next := -1
		if q.NextOffset != nil {
			next = *q.NextOffset
		}
		if [3]int{q.Matched, q.Returned, next} != want {
			t.Errorf("query %d: matched %d returned %d next %d, want %v", id, q.Matched, q.Returned, next, want)
		}
	}
	if s := text(3); !strings.Contains(s, id) || !strings.Contains(s, `"state": "dead"`) {
		t.Errorf("list_sessions: %s", s)
	}
	if s := text(7); !strings.Contains(s, `"report"`) {
		t.Errorf("get_session: %s", s)
	}
	if s := text(8); !strings.Contains(s, "id_ed25519") {
		t.Errorf("list_questions: %s", s)
	}
	if !got[9].Result.IsError {
		t.Error("unknown session: want isError")
	}
	if got[10].Error == nil || got[10].Error.Code != -32601 {
		t.Errorf("bogus method: %+v", got[10].Error)
	}
}
