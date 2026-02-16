package pipeline

import (
	"encoding/json"
	"fmt"
)

// shallowMergeJSON merges patch keys into base at the top level.
// Keys from patch override base. This is SHALLOW — nested objects
// are replaced wholesale, not deep-merged. This matches Claude Code's
// own updatedInput semantics.
func shallowMergeJSON(base, patch json.RawMessage) (json.RawMessage, error) {
	if len(base) == 0 && len(patch) == 0 {
		return nil, nil
	}
	if len(base) == 0 {
		return patch, nil
	}
	if len(patch) == 0 {
		return base, nil
	}

	var baseMap map[string]json.RawMessage
	if err := json.Unmarshal(base, &baseMap); err != nil {
		return nil, fmt.Errorf("shallowMergeJSON base: %w", err)
	}

	var patchMap map[string]json.RawMessage
	if err := json.Unmarshal(patch, &patchMap); err != nil {
		return nil, fmt.Errorf("shallowMergeJSON patch: %w", err)
	}

	for k, v := range patchMap {
		baseMap[k] = v
	}

	result, err := json.Marshal(baseMap)
	if err != nil {
		return nil, fmt.Errorf("shallowMergeJSON marshal: %w", err)
	}

	return result, nil
}
