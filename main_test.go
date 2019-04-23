package main

import (
	"testing"

	"github.com/appleboy/gofight"
	"github.com/stretchr/testify/assert"
)

func TestRoutes(t *testing.T) {
	r := gofight.New()
	r.GET("/admin").
		Run(New(), func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
			assert.Contains(t, r.Body.String(), "/google/login")
		})
}
