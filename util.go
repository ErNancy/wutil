package wutil

import (
	"net/http"
	"time"

	"golang.org/x/net/context"

	"goji.io"
	"goji.io/pat"
)

// OkHandler simply replies with a "200 OK" response (useful for load balancers
// and such).
func OkHandler(ctxt context.Context, res http.ResponseWriter, req *http.Request) {
	res.Write([]byte("OK"))
}

// ClearHandler clears a client's cookies.
func ClearHandler(ctxt context.Context, res http.ResponseWriter, req *http.Request) {
	expires := time.Now()

	// loop over defined cookies and set expiration, bad value
	for _, c := range req.Cookies() {
		http.SetCookie(res, &http.Cookie{
			Name:    c.Name,
			Expires: expires,
			Value:   "-",
			MaxAge:  -1,
		})
	}

	res.Write([]byte("cookies cleared."))
}

// RegisterUtils adds the OkHandler and ClearHandler to the passed mux.
func RegisterUtils(mux *goji.Mux) {
	mux.HandleFuncC(pat.Get("/k"), OkHandler)
	mux.HandleFuncC(pat.Get("/c"), ClearHandler)
}
