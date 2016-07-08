package wutil

import (
	"bytes"
	"crypto/sha1"
	"encoding/json"
	"errors"
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

	"goji.io"
	"goji.io/pat"
	"goji.io/pattern"

	"github.com/flosch/pongo2"
)

// lgr is the common interface used for logging.
type lgr func(string, ...interface{})

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
	path string

	// manifestPath is the name of the manifest file.
	manifestPath string

	// faviconPath is the path to the favicon.
	faviconPath string

	// manifest[name] (ie, the hashed path) -> info/data
	staticManifest map[string]string

	// processed static asset info/data
	staticInfo map[string]*os.FileInfo
	staticData map[string]*[]byte
	staticHash map[string]string

	// templates path in asset data
	templatesPath string

	// templatesSuffix is the affixed suffix for template names.
	templatesSuffix string

	// templates
	templates map[string]*pongo2.Template

	// logger
	logger lgr

	// ignore
	ignore []*regexp.Regexp
}

// AssetSetOption represents options when creating a new AssetSet.
type AssetSetOption func(*AssetSet)

// Path sets the root lookup path for the AssetSet.
func Path(path string) AssetSetOption {
	return func(as *AssetSet) {
		as.path = path
	}
}

// TemplatesPath changes the default template path in the AssetSet.
func TemplatesPath(path string) AssetSetOption {
	return func(as *AssetSet) {
		as.templatesPath = path
	}
}

// ManifestPath changes the default manifest path in the AssetSet.
func ManifestPath(path string) AssetSetOption {
	return func(as *AssetSet) {
		as.manifestPath = path
	}
}

// FaviconPath changes the default favicon path in the AssetSet.
func FaviconPath(path string) AssetSetOption {
	return func(as *AssetSet) {
		as.faviconPath = path
	}
}

// TemplatesSuffix changes the default template suffix in the AssetSet.
func TemplatesSuffix(suffix string) AssetSetOption {
	return func(as *AssetSet) {
		as.templatesSuffix = suffix
	}
}

// Ignore prevents files matching the supplied regexps to be excluded from
// being served from the AssetSet.
func Ignore(regexps ...*regexp.Regexp) AssetSetOption {
	return func(as *AssetSet) {
		as.ignore = append(as.ignore, regexps...)
	}
}

// Logger sets the logger for an AssetSet.
func Logger(l lgr) AssetSetOption {
	return func(as *AssetSet) {
		as.logger = l
	}
}

// NewAssetSet creates an asset set with the passed parameters.
/*staticPath, manifestPath, templatesPath string, ignore []*regexp.Regexp*/
func NewAssetSet(anFn assetNameFn, aFn assetFn, aiFn assetInfoFn, opts ...AssetSetOption) (*AssetSet, error) {
	as := &AssetSet{
		assetNameFn:     anFn,
		assetFn:         aFn,
		assetInfoFn:     aiFn,
		path:            "/_/",
		manifestPath:    "manifest.json",
		templatesPath:   "templates/",
		faviconPath:     "favicon.ico",
		templatesSuffix: ".html",
		logger:          log.Printf,
		ignore:          []*regexp.Regexp{},
	}

	// apply options
	for _, o := range opts {
		o(as)
	}

	if !strings.HasSuffix(as.path, "/") {
		return nil, errors.New("asset path must end with /")
	}
	if !strings.HasSuffix(as.templatesPath, "/") {
		return nil, errors.New("templates path must end with /")
	}

	// grab manifest bytes
	mfd, err := aFn(as.manifestPath)
	if err != nil {
		return nil, fmt.Errorf("could not read data from manifest '%s'", as.manifestPath)
	}

	// load manifest data
	var mf interface{}
	err = json.Unmarshal(mfd, &mf)
	if err != nil {
		return nil, fmt.Errorf("could not json.Unmarshal manifest '%s': %s", as.manifestPath, err)
	}

	// convert mf to actual map
	manifestMap, ok := mf.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("'%s' is not a valid manifest", as.manifestPath)
	}

	// create storage
	as.staticManifest = make(map[string]string)
	as.staticInfo = make(map[string]*os.FileInfo)
	as.staticData = make(map[string]*[]byte)
	as.staticHash = make(map[string]string)

	// process static assets
	ignoredCount := 0
	for name, v := range manifestMap {
		ignored := false

		// determine if the name is in the ignore list
		for _, re := range as.ignore {
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
				return nil, fmt.Errorf("invalid value for key '%s' in manifest '%s'", name, as.manifestPath)
			}

			data, err := aFn(hash)
			if err != nil {
				return nil, fmt.Errorf("asset %s (%s) not available", name, hash)
			}

			info, err := aiFn(hash)
			if err != nil {
				return nil, fmt.Errorf("asset info %s (%s) not available", name, hash)
			}

			as.staticManifest[name] = hash
			as.staticInfo[hash] = &info
			as.staticData[hash] = &data
			as.staticHash[hash] = fmt.Sprintf("%x", sha1.Sum(data))
		}
	}

	// create template storage
	as.templates = make(map[string]*pongo2.Template)

	// register asset filter
	pongo2.RegisterFilter("asset", as.Pongo2AssetFilter)

	// setup template set
	tplSet := pongo2.NewSet("", as)

	// loop over template assets and process
	for _, name := range anFn() {
		if strings.HasPrefix(name, as.templatesPath) && strings.HasSuffix(name, as.templatesSuffix) {
			n := name[len(as.templatesPath):]
			as.templates[n] = pongo2.Must(tplSet.FromFile(n))
		}
	}

	as.logger("processed static assets (processed: %d, ignored: %d)", len(as.staticManifest), ignoredCount)
	as.logger("processed templates (%d)", len(as.templates))

	return as, nil
}

// staticHandler retrieves the static asset from the AssetSet, sending it to
// the http endpoint.
func (as *AssetSet) staticHandler(name string, res http.ResponseWriter, req *http.Request) {
	// grab info
	ai, ok := as.staticInfo[name]
	if !ok {
		http.Error(res, http.StatusText(http.StatusNotFound), http.StatusNotFound)
		return
	}

	modtime := (*ai).ModTime()

	// check if-modified-since header, bail if present
	if t, err := time.Parse(http.TimeFormat, req.Header.Get("If-Modified-Since")); err == nil && modtime.Unix() <= t.Unix() {
		res.WriteHeader(http.StatusNotModified) // 304
		return
	}

	// grab hash
	hash, ok := as.staticHash[name]
	if !ok {
		http.Error(res, http.StatusText(http.StatusNotFound), http.StatusNotFound)
		return
	}

	// check If-None-Match header, bail if present and match to hash
	if req.Header.Get("If-None-Match") == hash {
		res.WriteHeader(http.StatusNotModified) // 304
		return
	}

	// grab data
	data, ok := as.staticData[name]
	if !ok {
		http.Error(res, http.StatusText(http.StatusNotFound), http.StatusNotFound)
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
func (as *AssetSet) StaticHandler(ctxt context.Context, res http.ResponseWriter, req *http.Request) {
	as.staticHandler(pattern.Path(ctxt)[1:], res, req)
}

// FaviconHandler is a helper that serves the static "favicon.ico" asset from
// the AssetSet.
func (as *AssetSet) FaviconHandler(ctxt context.Context, res http.ResponseWriter, req *http.Request) {
	as.staticHandler(as.faviconPath, res, req)
}

// -----------------------------------------------------------------------
// Pongo2 methods

// Abs see pongo2.TemplateLoader.Abs
func (as AssetSet) Abs(base, name string) string {
	return name
}

// Get see pongo2.TemplateLoader.Get
func (as AssetSet) Get(path string) (io.Reader, error) {
	data, err := as.assetFn(as.templatesPath + path)
	if err != nil {
		return nil, err
	}

	return bytes.NewReader(data), nil
}

// Pongo2AssetFilter is a filter that can be used in pongo2 templates to change
// the path of an asset.
func (as *AssetSet) Pongo2AssetFilter(in *pongo2.Value, param *pongo2.Value) (*pongo2.Value, *pongo2.Error) {
	// get value as string
	val := in.String()

	// load the path from the manifest and return if valid
	name, ok := as.staticManifest[val]
	if ok {
		return pongo2.AsValue(as.path + name), nil
	}

	// return error if asset not in manifest
	return nil, &pongo2.Error{
		Sender:   "filter:asset",
		ErrorMsg: fmt.Sprintf("asset '%s' not found", val),
	}
}

// ExecuteTemplate executes a template from the asset with the passed context.
func (as *AssetSet) ExecuteTemplate(res http.ResponseWriter, name string, context pongo2.Context) {
	// load template
	tpl, ok := as.templates[name]
	if !ok {
		http.Error(res, fmt.Sprintf("cannot load template %s", name), http.StatusInternalServerError)
		return
	}

	// execute
	tpl.ExecuteWriterUnbuffered(context, res)
}

// TemplateHandler handles a template.
func (as *AssetSet) TemplateHandler(tplName string, c ...pongo2.Context) func(context.Context, http.ResponseWriter, *http.Request) {
	pongoContext := pongo2.Context{}
	if len(c) > 0 {
		pongoContext = c[0]
	}

	return func(ctxt context.Context, res http.ResponseWriter, req *http.Request) {
		as.ExecuteTemplate(res, tplName, pongoContext)
	}
}

// -----------------------------------------------------------------------

// Register registers the AssetSet to the provided mux.
func (as *AssetSet) Register(mux *goji.Mux) {
	// add favicon handler only if the favicon.ico is present in the path.
	if false {
		mux.HandleFuncC(pat.Get("/favicon.ico"), as.FaviconHandler)
	}

	mux.HandleFuncC(pat.Get(as.path+"*"), as.StaticHandler)
	//mux.HandleFuncC(pat.Get("/"), as.TemplateHandler("index.html"))
}
