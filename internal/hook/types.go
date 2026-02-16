package hook

import (
	"encoding/json"
	"fmt"
	"maps"
)

// Input represents the JSON payload Claude Code sends to a hook via stdin.
// Known fields are extracted into struct fields; unknown fields are preserved
// in rawFields for transparent round-tripping.
//
// The Claude Code hook protocol uses snake_case for input fields:
//
//	session_id, transcript_path, cwd, permission_mode,
//	hook_event_name, tool_name, tool_input, tool_use_id
type Input struct {
	SessionID      string          `json:"session_id,omitempty"`
	TranscriptPath string          `json:"transcript_path,omitempty"`
	CWD            string          `json:"cwd,omitempty"`
	PermissionMode string          `json:"permission_mode,omitempty"`
	HookEventName  string          `json:"hook_event_name,omitempty"`
	ToolName       string          `json:"tool_name,omitempty"`
	ToolUseID      string          `json:"tool_use_id,omitempty"`
	ToolInput      json.RawMessage `json:"tool_input,omitempty"`

	// rawFields preserves the full original map for re-serialization,
	// ensuring unknown fields survive the round-trip.
	rawFields map[string]json.RawMessage
}

// UnmarshalJSON implements custom unmarshaling that preserves unknown fields.
func (inp *Input) UnmarshalJSON(data []byte) error {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return fmt.Errorf("hook.Input unmarshal: %w", err)
	}

	inp.rawFields = raw

	if v, ok := raw["session_id"]; ok {
		if err := json.Unmarshal(v, &inp.SessionID); err != nil {
			return fmt.Errorf("hook.Input unmarshal session_id: %w", err)
		}
	}
	if v, ok := raw["transcript_path"]; ok {
		if err := json.Unmarshal(v, &inp.TranscriptPath); err != nil {
			return fmt.Errorf("hook.Input unmarshal transcript_path: %w", err)
		}
	}
	if v, ok := raw["cwd"]; ok {
		if err := json.Unmarshal(v, &inp.CWD); err != nil {
			return fmt.Errorf("hook.Input unmarshal cwd: %w", err)
		}
	}
	if v, ok := raw["permission_mode"]; ok {
		if err := json.Unmarshal(v, &inp.PermissionMode); err != nil {
			return fmt.Errorf("hook.Input unmarshal permission_mode: %w", err)
		}
	}
	if v, ok := raw["hook_event_name"]; ok {
		if err := json.Unmarshal(v, &inp.HookEventName); err != nil {
			return fmt.Errorf("hook.Input unmarshal hook_event_name: %w", err)
		}
	}
	if v, ok := raw["tool_name"]; ok {
		if err := json.Unmarshal(v, &inp.ToolName); err != nil {
			return fmt.Errorf("hook.Input unmarshal tool_name: %w", err)
		}
	}
	if v, ok := raw["tool_use_id"]; ok {
		if err := json.Unmarshal(v, &inp.ToolUseID); err != nil {
			return fmt.Errorf("hook.Input unmarshal tool_use_id: %w", err)
		}
	}
	if v, ok := raw["tool_input"]; ok {
		inp.ToolInput = v
	}

	return nil
}

// MarshalJSON implements custom marshaling that includes unknown fields.
func (inp Input) MarshalJSON() ([]byte, error) {
	out := make(map[string]json.RawMessage, len(inp.rawFields)+8)

	// Copy all raw fields first (preserves unknowns).
	maps.Copy(out, inp.rawFields)

	// Overwrite known fields with current struct values.
	if inp.SessionID != "" {
		b, err := json.Marshal(inp.SessionID)
		if err != nil {
			return nil, fmt.Errorf("hook.Input marshal session_id: %w", err)
		}
		out["session_id"] = b
	}
	if inp.TranscriptPath != "" {
		b, err := json.Marshal(inp.TranscriptPath)
		if err != nil {
			return nil, fmt.Errorf("hook.Input marshal transcript_path: %w", err)
		}
		out["transcript_path"] = b
	}
	if inp.CWD != "" {
		b, err := json.Marshal(inp.CWD)
		if err != nil {
			return nil, fmt.Errorf("hook.Input marshal cwd: %w", err)
		}
		out["cwd"] = b
	}
	if inp.PermissionMode != "" {
		b, err := json.Marshal(inp.PermissionMode)
		if err != nil {
			return nil, fmt.Errorf("hook.Input marshal permission_mode: %w", err)
		}
		out["permission_mode"] = b
	}
	if inp.HookEventName != "" {
		b, err := json.Marshal(inp.HookEventName)
		if err != nil {
			return nil, fmt.Errorf("hook.Input marshal hook_event_name: %w", err)
		}
		out["hook_event_name"] = b
	}
	if inp.ToolName != "" {
		b, err := json.Marshal(inp.ToolName)
		if err != nil {
			return nil, fmt.Errorf("hook.Input marshal tool_name: %w", err)
		}
		out["tool_name"] = b
	}
	if inp.ToolUseID != "" {
		b, err := json.Marshal(inp.ToolUseID)
		if err != nil {
			return nil, fmt.Errorf("hook.Input marshal tool_use_id: %w", err)
		}
		out["tool_use_id"] = b
	}
	if inp.ToolInput != nil {
		out["tool_input"] = inp.ToolInput
	}

	return json.Marshal(out)
}

// WithToolInput returns a copy of the Input with ToolInput replaced.
// The copy shares the same rawFields reference but updates the tool_input key.
func (inp Input) WithToolInput(merged json.RawMessage) Input {
	cp := inp

	// Deep-copy rawFields so we don't mutate the original.
	cp.rawFields = make(map[string]json.RawMessage, len(inp.rawFields))
	maps.Copy(cp.rawFields, inp.rawFields)

	cp.ToolInput = merged
	cp.rawFields["tool_input"] = merged

	return cp
}

// HookSpecificOutput contains hook-protocol-specific fields in the output.
type HookSpecificOutput struct {
	HookEventName            string          `json:"hookEventName,omitempty"`
	PermissionDecision       string          `json:"permissionDecision,omitempty"`
	PermissionDecisionReason string          `json:"permissionDecisionReason,omitempty"`
	UpdatedInput             json.RawMessage `json:"updatedInput,omitempty"`
	AdditionalContext        string          `json:"additionalContext,omitempty"`
}

// Output represents the JSON payload a hook writes to stdout.
type Output struct {
	HookSpecificOutput HookSpecificOutput `json:"hookSpecificOutput"`
	Continue           *bool              `json:"continue,omitempty"`
	SuppressOutput     *bool              `json:"suppressOutput,omitempty"`
	SystemMessage      string             `json:"systemMessage,omitempty"`
}
