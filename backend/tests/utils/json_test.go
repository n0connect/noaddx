package utils

import (
	"bytes"
	"net/http/httptest"
	"strings"
	"testing"

	"noaddx/internal/config"
	"noaddx/internal/models"
	"noaddx/internal/utils"
	"noaddx/tests/testutil"
)

func setupJSONTestEnv(t *testing.T) {
	t.Helper()
	testutil.SetupTestEnv(t)
	t.Cleanup(func() {
		testutil.TeardownTestEnv(t)
	})
}

func TestDecodeJSONRequest_ValidDepth(t *testing.T) {
	setupJSONTestEnv(t)

	// Test with valid depth (depth 2 - RegisterRequest with nested PoW object)
	jsonBody := `{
		"confirm": false,
		"pow": {"challenge": "00", "solution": "1", "salt": "00", "difficulty": 18}
	}`

	req := httptest.NewRequest("POST", "/api/v2/register", bytes.NewBufferString(jsonBody))
	req.Header.Set("Content-Type", "application/json")

	var registerReq models.RegisterRequest
	err := utils.DecodeJSONRequest(req, &registerReq)
	if err != nil {
		t.Fatalf("DecodeJSONRequest() failed with valid depth: %v", err)
	}

	if registerReq.PoW == nil || registerReq.PoW.Solution != "1" {
		t.Errorf("Expected nested pow.solution '1', got %+v", registerReq.PoW)
	}
}

// listBody is a depth-2 shape (object containing an array) used by array-depth tests
type listBody struct {
	Items []string `json:"items"`
}

func TestDecodeJSONRequest_ExceedsMaxDepth(t *testing.T) {
	setupJSONTestEnv(t)

	// Create deeply nested JSON (depth > MaxJSONDepth = 2)
	// Build a JSON with 5 levels of nesting (should be rejected)
	nestedJSON := strings.Repeat(`{"a":`, 5) + `"value"` + strings.Repeat(`}`, 5)

	req := httptest.NewRequest("POST", "/api/v2/test", bytes.NewBufferString(nestedJSON))
	req.Header.Set("Content-Type", "application/json")

	var result map[string]interface{}
	err := utils.DecodeJSONRequest(req, &result)
	if err == nil {
		t.Error("DecodeJSONRequest() should have failed with deeply nested JSON")
	}

	if !strings.Contains(err.Error(), "nesting depth exceeds maximum") {
		t.Errorf("Expected depth limit error, got: %v", err)
	}
}

func TestDecodeJSONRequest_ValidShallowDepth(t *testing.T) {
	setupJSONTestEnv(t)

	// Test with shallow depth (depth 1 - LoginRequest) carrying a real derived auth key
	authKey := testutil.NewAuthKey(t)
	jsonBody := `{
		"auth_key": "` + authKey + `"
	}`

	req := httptest.NewRequest("POST", "/api/v2/login", bytes.NewBufferString(jsonBody))
	req.Header.Set("Content-Type", "application/json")

	var loginReq models.LoginRequest
	err := utils.DecodeJSONRequest(req, &loginReq)
	if err != nil {
		t.Fatalf("DecodeJSONRequest() failed with shallow depth: %v", err)
	}

	if loginReq.AuthKey != authKey {
		t.Errorf("Expected auth_key %q, got %q", authKey, loginReq.AuthKey)
	}
}

func TestDecodeJSONRequest_ArrayDepth(t *testing.T) {
	setupJSONTestEnv(t)

	// Test with array nesting (depth 2)
	jsonBody := `{
		"items": ["a", "b"]
	}`

	req := httptest.NewRequest("POST", "/api/v2/test", bytes.NewBufferString(jsonBody))
	req.Header.Set("Content-Type", "application/json")

	var body listBody
	err := utils.DecodeJSONRequest(req, &body)
	if err != nil {
		t.Fatalf("DecodeJSONRequest() failed with array depth: %v", err)
	}

	if len(body.Items) != 2 {
		t.Errorf("Expected 2 items, got %d", len(body.Items))
	}
}

func TestDecodeJSONRequest_UnknownFields(t *testing.T) {
	setupJSONTestEnv(t)

	// Test that unknown fields are rejected
	jsonBody := `{
		"auth_key": "` + testutil.NewAuthKey(t) + `",
		"malicious_field": "attack"
	}`

	req := httptest.NewRequest("POST", "/api/v2/login", bytes.NewBufferString(jsonBody))
	req.Header.Set("Content-Type", "application/json")

	var loginReq models.LoginRequest
	err := utils.DecodeJSONRequest(req, &loginReq)
	if err == nil {
		t.Error("DecodeJSONRequest() should have rejected unknown fields")
	}
}

func TestDecodeJSONRequest_SizeLimit(t *testing.T) {
	setupJSONTestEnv(t)

	// Test that large request bodies are rejected
	maxBytes := config.GetMaxRequestBodyBytes()
	if maxBytes <= 0 {
		t.Fatal("MAX_REQUEST_BODY_BYTES not configured in test env")
	}
	largeBody := strings.Repeat("A", maxBytes+1)

	req := httptest.NewRequest("POST", "/api/v2/test", bytes.NewBufferString(largeBody))
	req.Header.Set("Content-Type", "application/json")

	var result map[string]interface{}
	err := utils.DecodeJSONRequest(req, &result)
	if err == nil {
		t.Error("DecodeJSONRequest() should have rejected large request body")
	}

	if !strings.Contains(err.Error(), "too large") {
		t.Errorf("Expected size limit error, got: %v", err)
	}
}

func TestDecodeJSONRequest_InvalidJSON(t *testing.T) {
	setupJSONTestEnv(t)

	// Test with invalid JSON
	invalidJSON := `{invalid json}`

	req := httptest.NewRequest("POST", "/api/v2/test", bytes.NewBufferString(invalidJSON))
	req.Header.Set("Content-Type", "application/json")

	var result map[string]interface{}
	err := utils.DecodeJSONRequest(req, &result)
	if err == nil {
		t.Error("DecodeJSONRequest() should have failed with invalid JSON")
	}
}

func TestDecodeJSONRequest_EmptyBody(t *testing.T) {
	setupJSONTestEnv(t)

	// Test with empty body
	req := httptest.NewRequest("POST", "/api/v2/register", bytes.NewBufferString(""))
	req.Header.Set("Content-Type", "application/json")

	var registerReq models.RegisterRequest
	err := utils.DecodeJSONRequest(req, &registerReq)
	// Empty body should be handled gracefully (may succeed or fail depending on struct)
	// This test just ensures no panic occurs
	if err != nil {
		t.Logf("DecodeJSONRequest() with empty body returned error (expected): %v", err)
	}
}

func TestDecodeJSONRequest_MaxDepthBoundary(t *testing.T) {
	setupJSONTestEnv(t)

	// Test with exactly MaxJSONDepth (2) levels - should succeed
	maxDepth := config.GetMaxJSONDepth()
	if maxDepth <= 0 {
		t.Fatal("MAX_JSON_DEPTH not configured in test env")
	}
	nestedJSON := strings.Repeat(`{"a":`, maxDepth) + `"value"` + strings.Repeat(`}`, maxDepth)

	req := httptest.NewRequest("POST", "/api/v2/test", bytes.NewBufferString(nestedJSON))
	req.Header.Set("Content-Type", "application/json")

	var result map[string]interface{}
	err := utils.DecodeJSONRequest(req, &result)
	// Should succeed at exactly MaxJSONDepth (2)
	if err != nil {
		t.Errorf("DecodeJSONRequest() at max depth (2) should succeed, got error: %v", err)
	}
}

func TestDecodeJSONRequest_MaxDepthPlusOne(t *testing.T) {
	setupJSONTestEnv(t)

	// Test with MaxJSONDepth + 1 levels (3 levels, should fail)
	maxDepth := config.GetMaxJSONDepth()
	if maxDepth <= 0 {
		t.Fatal("MAX_JSON_DEPTH not configured in test env")
	}
	nestedJSON := strings.Repeat(`{"a":`, maxDepth+1) + `"value"` + strings.Repeat(`}`, maxDepth+1)

	req := httptest.NewRequest("POST", "/api/v2/test", bytes.NewBufferString(nestedJSON))
	req.Header.Set("Content-Type", "application/json")

	var result map[string]interface{}
	err := utils.DecodeJSONRequest(req, &result)
	if err == nil {
		t.Error("DecodeJSONRequest() should have failed with MaxJSONDepth+1 levels (3 levels)")
	}

	if !strings.Contains(err.Error(), "nesting depth exceeds maximum") {
		t.Errorf("Expected depth limit error, got: %v", err)
	}
}

func TestDecodeJSONRequest_Depth3_ShouldFail(t *testing.T) {
	setupJSONTestEnv(t)

	// Test with depth 3 (should fail, max is 2)
	nestedJSON := `{"a": {"b": {"c": "value"}}}`

	req := httptest.NewRequest("POST", "/api/v2/test", bytes.NewBufferString(nestedJSON))
	req.Header.Set("Content-Type", "application/json")

	var result map[string]interface{}
	err := utils.DecodeJSONRequest(req, &result)
	if err == nil {
		t.Error("DecodeJSONRequest() should have failed with depth 3")
	}

	if !strings.Contains(err.Error(), "nesting depth exceeds maximum") {
		t.Errorf("Expected depth limit error, got: %v", err)
	}
}

func TestDecodeJSONRequest_Depth2_ShouldSucceed(t *testing.T) {
	setupJSONTestEnv(t)

	// Test with depth 2 (should succeed: object containing an array)
	jsonBody := `{"items": ["a", "b"]}`

	req := httptest.NewRequest("POST", "/api/v2/test", bytes.NewBufferString(jsonBody))
	req.Header.Set("Content-Type", "application/json")

	var body listBody
	err := utils.DecodeJSONRequest(req, &body)
	if err != nil {
		t.Errorf("DecodeJSONRequest() should succeed with depth 2, got error: %v", err)
	}

	if len(body.Items) != 2 {
		t.Errorf("Expected 2 items, got %d", len(body.Items))
	}
}

// Regression: a second top-level value must be rejected (parser-differential PoW bypass)
func TestDecodeJSONRequest_TrailingValue_Rejected(t *testing.T) {
	setupJSONTestEnv(t)

	for _, body := range []string{
		`{"confirm":false,"pow":{"challenge":"x","solution":"1","salt":"y"}} {}`,
		`{"auth_key":"x"}{"auth_key":"y"}`,
		`{"auth_key":"x"} 1`,
	} {
		req := httptest.NewRequest("POST", "/api/v2/register", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		var v map[string]interface{}
		if err := utils.DecodeJSONRequest(req, &v); err == nil {
			t.Errorf("DecodeJSONRequest() accepted trailing data: %q", body)
		}
	}
}
