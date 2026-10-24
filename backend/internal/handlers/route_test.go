package handlers

import (
	"net/http/httptest"
	"testing"
)

func TestParseConversationRoute_Whitelist(t *testing.T) {
	const id = "3b241101-e2bb-4255-8caf-4136c566a962"
	ok := map[string]string{
		"/api/v2/conversations":                     "",
		"/api/v2/conversations/" + id:               "",
		"/api/v2/conversations/" + id + "/messages": "messages",
		"/api/v2/conversations/" + id + "/read":     "read",
	}
	for path, wantSub := range ok {
		_, sub, valid := parseConversationRoute(path)
		if !valid || sub != wantSub {
			t.Errorf("%s: valid=%v sub=%q", path, valid, sub)
		}
	}
	for _, path := range []string{
		"/api/v2/conversations/",
		"/api/v2/conversations/" + id + "/",
		"/api/v2/conversations/" + id + "/messages/x",
		"/api/v2/conversations/" + id + "/members",
		"/api/v2/conversations/3B241101-E2BB-4255-8CAF-4136C566A962",   // non-canonical case
		"/api/v2/conversations/3b241101-e2bb-1255-8caf-4136c566a962",   // not v4
		"/api/v2/conversations/{3b241101-e2bb-4255-8caf-4136c566a962}", // braces
		"/api/v2/conversations/../me",
	} {
		if _, _, valid := parseConversationRoute(path); valid {
			t.Errorf("%s accepted", path)
		}
	}
}

func TestParseAfter_Whitelist(t *testing.T) {
	for query, want := range map[string]bool{
		"":                           true,
		"after=0":                    true,
		"after=42":                   true,
		"after=-1":                   false,
		"after=1e3":                  false,
		"after=":                     false,
		"after=1&after=2":            false,
		"after=1&limit=5":            false,
		"before=1":                   false,
		"after=99999999999999999999": false,
	} {
		r := httptest.NewRequest("GET", "/api/v2/conversations/x/messages?"+query, nil)
		if _, valid := parseAfter(r); valid != want {
			t.Errorf("query %q: valid=%v want %v", query, valid, want)
		}
	}
}
