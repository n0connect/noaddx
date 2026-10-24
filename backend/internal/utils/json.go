package utils

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"noaddress/internal/config"
)

func maxRequestBodyBytes() (int, error) {
	maxBytes := config.GetMaxRequestBodyBytes()
	if maxBytes <= 0 {
		return 0, fmt.Errorf("MAX_REQUEST_BODY_BYTES not configured")
	}
	return maxBytes, nil
}

func maxJSONDepth() (int, error) {
	maxDepth := config.GetMaxJSONDepth()
	if maxDepth <= 0 {
		return 0, fmt.Errorf("MAX_JSON_DEPTH not configured")
	}
	return maxDepth, nil
}

// CheckJSONDepth checks the maximum nesting depth of a JSON document
// Returns the maximum depth and any error encountered
func CheckJSONDepth(data []byte) (int, error) {
	maxDepthLimit, err := maxJSONDepth()
	if err != nil {
		return 0, err
	}

	decoder := json.NewDecoder(bytes.NewReader(data))
	depth := 0
	maxDepth := 0

	for {
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return 0, fmt.Errorf("invalid JSON: %w", err)
		}

		// Track depth based on delimiter tokens
		switch token {
		case json.Delim('{'), json.Delim('['):
			depth++
			if depth > maxDepth {
				maxDepth = depth
			}
			if depth > maxDepthLimit {
				return maxDepth, fmt.Errorf("JSON nesting depth exceeds maximum (%d levels)", maxDepthLimit)
			}
		case json.Delim('}'), json.Delim(']'):
			depth--
			if depth < 0 {
				return 0, fmt.Errorf("invalid JSON: unmatched closing delimiter")
			}
		}
	}

	return maxDepth, nil
}

// DecodeJSONRequest decodes a JSON request body into the provided struct
// SECURITY: Limits request body size and nesting depth to prevent DoS attacks
func DecodeJSONRequest(r *http.Request, v interface{}) error {
	maxBytes, err := maxRequestBodyBytes()
	if err != nil {
		return err
	}

	// Limit request body size to prevent memory exhaustion DoS
	limitedReader := io.LimitReader(r.Body, int64(maxBytes))

	// Read entire body to check depth (we need to read it anyway for decoding)
	bodyBytes, err := io.ReadAll(limitedReader)
	if err != nil {
		return fmt.Errorf("failed to read request body: %w", err)
	}

	// Check if body exceeds size limit
	if len(bodyBytes) >= maxBytes {
		return fmt.Errorf("request body too large (max %d bytes)", maxBytes)
	}

	// Check JSON depth before decoding
	if _, err := CheckJSONDepth(bodyBytes); err != nil {
		return err
	}

	// Decode JSON into struct
	decoder := json.NewDecoder(bytes.NewReader(bodyBytes))
	decoder.DisallowUnknownFields() // Security: reject unknown fields

	if err := decoder.Decode(v); err != nil {
		return fmt.Errorf("invalid JSON: %w", err)
	}

	// Exactly one JSON value per body: trailing data enables parser-differential bypasses
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return fmt.Errorf("invalid JSON: trailing data after top-level value")
	}

	return nil
}

// EncodeJSONResponse writes a JSON response with the given status code
func EncodeJSONResponse(w http.ResponseWriter, data interface{}, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(data)
}
