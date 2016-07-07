package wutil

import (
	"bytes"
	"crypto/sha1"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"mime"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"golang.org/x/net/context"

	"github.com/flosch/pongo2"
	"goji.io/pat"
)

// TemplatesSuffix is the affixed suffix for template names.
var TemplatesSuffix string = ".html"

type assetNameFn func() []string
type assetFn func(string) ([]byte, error)
type assetInfoFn func(string) (os.FileInfo, error)

// AssetSet is a collection of static assets.
type AssetSet struct {
	// retrieval functions
	assetNameFn assetNameFn
	assetFn     assetFn
	assetInfoFn assetInfoFn

	// path for serving static assets
	staticPath string

	// manifest[name] (ie, the hashed path) -> info/data
	staticManifest map[string]string

	// processed static asset info/data
	staticInfo map[string]*os.FileInfo
	staticData map[string]*[]byte
	staticHash map[string]string

	// templates path in asset data
	templatesPath string

	// templates
	templates map[string]*pongo2.Template
}

// NewAssetSet creates an asset set with the passed parameters.
func NewAssetSet(anFn assetNameFn, aFn assetFn, aiFn assetInfoFn, staticPath, manifestPath, templatesPath string, ignore []*regexp.Regexp) *AssetSet {
	a := AssetSet{
		assetNameFn:   anFn,
		assetFn:       aFn,
		assetInfoFn:   aiFn,
		staticPath:    staticPath,
		templatesPath: templatesPath,
	}

	// grab manifest bytes
	mfd, err := aFn(manifestPath)
	if err != nil {
		panic(fmt.Errorf("could not read data from manifest '%s'", manifestPath))
	}

	// load manifest data
	var mf interface{}
	err = json.Unmarshal(mfd, &mf)
	if err != nil {
		panic(fmt.Errorf("could not json.Unmarshal manifest '%s': %s", manifestPath, err))
	}

	// convert mf to actual map
	manifestMap, ok := mf.(map[string]interface{})
	if !ok {
		panic(fmt.Errorf("'%s' is not a valid manifest", manifestPath))
	}

	// create storage
	a.staticManifest = make(map[string]string)
	a.staticInfo = make(map[string]*os.FileInfo)
	a.staticData = make(map[string]*[]byte)
	a.staticHash = make(map[string]string)

	// process static assets
	ignoredCount := 0
	for name, v := range manifestMap {
		ignored := false

		// determine if the name is in the ignore list
		for _, re := range ignore {
			if re.MatchString(name) {
				ignored = true
				ignoredCount++
				break
			}
		}

		// only process if the asset is not on ignore list
		if !ignored {
			hash, ok := v.(string)
			if !ok {
				panic(fmt.Errorf("invalid value for key '%s' in manifest '%s'", name, manifestPath))
			}

			data, err := aFn(hash)
			if err != nil {
				panic(fmt.Errorf("asset %s (%s) not available", name, hash))
			}

			info, err := aiFn(hash)
			if err != nil {
				panic(fmt.Errorf("asset info %s (%s) not available", name, hash))
			}

			a.staticManifest[name] = hash
			a.staticInfo[hash] = &info
			a.staticData[hash] = &data
			a.staticHash[hash] = fmt.Sprintf("%x", sha1.Sum(data))

			//a.staticManifest[hash] = name
			//a.staticInfo[name] = &info
			//a.staticData[name] = &data
		}
	}

	// create template storage
	a.templates = make(map[string]*pongo2.Template)

	// register asset filter
	pongo2.RegisterFilter("asset", a.Pongo2AssetFilter)

	// setup template set
	tplSet := pongo2.NewSet("", a)

	// loop over template assets and process
	for _, name := range anFn() {
		if strings.HasPrefix(name, a.templatesPath) && strings.HasSuffix(name, TemplatesSuffix) {
			n := name[len(a.templatesPath):]
			a.templates[n] = pongo2.Must(tplSet.FromFile(n))
		}
	}

	log.Printf("processed static assets (processed: %d, ignored: %d)", len(a.staticManifest), ignoredCount)
	log.Printf("processed templates (%d)", len(a.templates))

	return &a
}

func (a *AssetSet) staticHandler(name string, res http.ResponseWriter, req *http.Request) {
	// grab info
	ai, ok := a.staticInfo[name]
	if !ok {
		http.Error(res, http.StatusText(404), 404)
		return
	}

	modtime := (*ai).ModTime()

	// check if-modified-since header, bail if present
	if t, err := time.Parse(http.TimeFormat, req.Header.Get("If-Modified-Since")); err == nil && modtime.Unix() <= t.Unix() {
		res.WriteHeader(http.StatusNotModified) // 304
		return
	}

	// grab hash
	hash, ok := a.staticHash[name]
	if !ok {
		http.Error(res, http.StatusText(404), 404)
		return
	}

	// check If-None-Match header, bail if present and match to hash
	if req.Header.Get("If-None-Match") == hash {
		res.WriteHeader(http.StatusNotModified) // 304
		return
	}

	// grab data
	data, ok := a.staticData[name]
	if !ok {
		http.Error(res, http.StatusText(404), 404)
		return
	}

	// determine content type
	typ := "application/octet-stream"
	pos := strings.LastIndex(name, ".")
	if pos >= 0 {
		ext := name[pos:]
		if ext == ".ico" {
			// force content type for .ico
			typ = "image/x-icon"
		} else {
			typ = mime.TypeByExtension(ext)
		}
	}

	// set headers
	res.Header().Set("Content-Type", typ)
	res.Header().Set("Date", time.Now().Format(http.TimeFormat))

	// cache headers
	res.Header().Set("Cache-Control", "public, no-transform, max-age=31536000")
	res.Header().Set("Expires", time.Now().AddDate(1, 0, 0).Format(http.TimeFormat))
	res.Header().Set("Last-Modified", modtime.Format(http.TimeFormat))
	res.Header().Set("ETag", hash)

	// write data to response
	res.Write(*data)
}

// StaticHandler serves static assets from the AssetSet.
func (a *AssetSet) StaticHandler(ctxt context.Context, res http.ResponseWriter, req *http.Request) {
	a.staticHandler(pat.Param(ctxt, "*")[1:], res, req)
}

// FaviconHandler is a helper that serves the static "favicon.ico" asset from
// the AssetSet.
func (a *AssetSet) FaviconHandler(ctxt context.Context, res http.ResponseWriter, req *http.Request) {
	a.staticHandler("favicon.ico", res, req)
}

// -----------------------------------------------------------------------
// Pongo2 methods

// Abs see pongo2.TemplateLoader.Abs
func (a AssetSet) Abs(base, name string) string {
	return name
}

// Get see pongo2.TemplateLoader.Get
func (a AssetSet) Get(path string) (io.Reader, error) {
	data, err := a.assetFn(a.templatesPath + path)
	if err != nil {
		return nil, err
	}

	return bytes.NewReader(data), nil
}

// Pongo2AssetFilter is a filter that can be used in pongo2 templates to change
// the path of an asset.
func (a *AssetSet) Pongo2AssetFilter(in *pongo2.Value, param *pongo2.Value) (*pongo2.Value, *pongo2.Error) {
	// get value as string
	val := in.String()

	// load the path from the manifest and return if valid
	name, ok := a.staticManifest[val]
	if ok {
		return pongo2.AsValue(a.staticPath + name), nil
	}

	// return error if asset not in manifest
	return nil, &pongo2.Error{
		Sender:   "filter:asset",
		ErrorMsg: fmt.Sprintf("asset '%s' not found", val),
	}
}

// ExecuteTemplate executes a template from the asset with the passed context.
func (a *AssetSet) ExecuteTemplate(res http.ResponseWriter, name string, context pongo2.Context) {
	// load template
	tpl, ok := a.templates[name]
	if !ok {
		http.Error(res, fmt.Sprintf("cannot load template %s", name), http.StatusInternalServerError)
		return
	}

	// execute
	tpl.ExecuteWriterUnbuffered(context, res)
}

// TemplateHandler handles a template.
func (a *AssetSet) TemplateHandler(tplName string, c ...pongo2.Context) func(context.Context, http.ResponseWriter, *http.Request) {
	pongoContext := pongo2.Context{}
	if len(c) > 0 {
		pongoContext = c[0]
	}

	return func(ctxt context.Context, res http.ResponseWriter, req *http.Request) {
		a.ExecuteTemplate(res, tplName, pongoContext)
	}
}
