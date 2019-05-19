package main

import (
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCount(t *testing.T) {

	tests := []struct {
		name string
		uri  string
		want string
	}{
		{"Admin", "/admin", "Sign in - Google Accounts"},
	}

	ts := httptest.NewServer(BasicEngine())
	defer ts.Close()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			url := ts.URL + tt.uri
			resp, _ := http.Get(url)
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("got %d, want %d", resp.StatusCode, http.StatusOK)
			}
			respBody, _ := ioutil.ReadAll(resp.Body)
			resp.Body.Close()
			got := string(respBody)
			if !strings.Contains(got, tt.want) {
				t.Errorf("got %s, Want %s", got, tt.want)
			}
		})
	}
}
