package main

import (
	"testing"

	"github.com/appleboy/gofight"
	"github.com/stretchr/testify/assert"
)

func TestRoutes(t *testing.T) {
	r := gofight.New()
	r.GET("/admin").
		Run(BasicEngine(), func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
			assert.Contains(t, r.Body.String(), "/google/login")
		})
	r.GET("/").
		Run(BasicEngine(), func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
			assert.Contains(t, r.Body.String(), "Admin page")
		})

}
