package hook

import (
	"encoding/json"
	"testing"
)

func TestInputRoundTrip(t *testing.T) {
	raw := `{
		"session_id": "abc-123",
		"transcript_path": "/tmp/session",
		"hook_event_name": "PreToolUse",
		"tool_name": "Bash",
		"tool_use_id": "tu-456",
		"cwd": "/home/user/project",
		"tool_input": {"command": "ls -la"},
		"unknownField": "should survive",
		"anotherUnknown": 42
	}`

	var inp Input
	if err := json.Unmarshal([]byte(raw), &inp); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	// Verify known fields.
	if inp.SessionID != "abc-123" {
		t.Errorf("SessionID = %q, want %q", inp.SessionID, "abc-123")
	}
	if inp.HookEventName != "PreToolUse" {
		t.Errorf("HookEventName = %q, want %q", inp.HookEventName, "PreToolUse")
	}
	if inp.ToolName != "Bash" {
		t.Errorf("ToolName = %q, want %q", inp.ToolName, "Bash")
	}

	// Re-marshal and verify unknown fields survive.
	out, err := json.Marshal(inp)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	var roundTripped map[string]json.RawMessage
	if err := json.Unmarshal(out, &roundTripped); err != nil {
		t.Fatalf("Unmarshal round-tripped: %v", err)
	}

	if _, ok := roundTripped["unknownField"]; !ok {
		t.Error("unknownField lost during round-trip")
	}
	if _, ok := roundTripped["anotherUnknown"]; !ok {
		t.Error("anotherUnknown lost during round-trip")
	}

	var unknownVal string
	if err := json.Unmarshal(roundTripped["unknownField"], &unknownVal); err != nil {
		t.Fatalf("Unmarshal unknownField: %v", err)
	}
	if unknownVal != "should survive" {
		t.Errorf("unknownField = %q, want %q", unknownVal, "should survive")
	}
}

func TestWithToolInput(t *testing.T) {
	raw := `{
		"session_id": "abc",
		"tool_input": {"command": "original"},
		"extraField": true
	}`

	var inp Input
	if err := json.Unmarshal([]byte(raw), &inp); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	newToolInput := json.RawMessage(`{"command": "modified", "extra": true}`)
	cp := inp.WithToolInput(newToolInput)

	// Verify the copy has the new ToolInput.
	var cpTool map[string]any
	if err := json.Unmarshal(cp.ToolInput, &cpTool); err != nil {
		t.Fatalf("Unmarshal copy ToolInput: %v", err)
	}
	if cpTool["command"] != "modified" {
		t.Errorf("copy command = %v, want %q", cpTool["command"], "modified")
	}

	// Verify the original is unchanged.
	var origTool map[string]any
	if err := json.Unmarshal(inp.ToolInput, &origTool); err != nil {
		t.Fatalf("Unmarshal original ToolInput: %v", err)
	}
	if origTool["command"] != "original" {
		t.Errorf("original command = %v, want %q", origTool["command"], "original")
	}

	// Verify unknown fields survive on the copy.
	out, err := json.Marshal(cp)
	if err != nil {
		t.Fatalf("Marshal copy: %v", err)
	}
	var cpMap map[string]json.RawMessage
	if err := json.Unmarshal(out, &cpMap); err != nil {
		t.Fatalf("Unmarshal copy map: %v", err)
	}
	if _, ok := cpMap["extraField"]; !ok {
		t.Error("extraField lost in WithToolInput copy")
	}
}

func TestOutputMarshal(t *testing.T) {
	cont := true
	out := Output{
		HookSpecificOutput: HookSpecificOutput{
			PermissionDecision:       "deny",
			PermissionDecisionReason: "blocked by policy",
		},
		Continue: &cont,
	}

	data, err := json.Marshal(out)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	var parsed Output
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	if parsed.HookSpecificOutput.PermissionDecision != "deny" {
		t.Errorf("PermissionDecision = %q, want %q",
			parsed.HookSpecificOutput.PermissionDecision, "deny")
	}
	if parsed.Continue == nil || !*parsed.Continue {
		t.Error("Continue should be true")
	}
}
