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

const (
	// DefaultAssetFilterName is the dafault asset filter name used in asset
	// sets.
	DefaultAssetFilterName = "asset"

	// DefaultCsrfVariableName is the default csrf variable name used in asset
	// sets.
	DefaultCsrfVariableName = "__csrf_token__"

	// DefaultAssetPath is the default asset path prefix for static assets.
	DefaultAssetPath = "/_/"

	// DefaultManifestPath is the path to the manifest in the asset set to use
	// to determine what assets to serve.
	DefaultManifestPath = "manifest.json"

	// DefaultTemplatesPath is the path to templates in the asset set.
	DefaultTemplatesPath = "templates/"

	// DefaultFaviconPath is the path to the favicon.
	DefaultFaviconPath = "favicon.ico"

	// DefaultTemplatesSuffix is the default suffix to use for templates.
	DefaultTemplatesSuffix = ".html"
)

// lgr is the common interface used for logging.
type lgr func(string, ...interface{})

type assetNameFn func() []string
type assetFn func(string) ([]byte, error)
type assetInfoFn func(string) (os.FileInfo, error)

type asset struct {
	info        *os.FileInfo
	data        *[]byte
	sha1        string
	contentType string
}

// AssetSet is a collection of static assets.
type AssetSet struct {
	// retrieval functions
	assetNameFn assetNameFn
	assetFn     assetFn
	assetInfoFn assetInfoFn

	// assetFilterName is the name used in templates for the asset filter.
	assetFilterName string

	// csrfVariableName is the name to add to the template context for the
	// generate csrf token.
	csrfVariableName string

	// csrf is a func that returns the csrf token for the request.
	csrf func(context.Context, *http.Request) string

	// assetPath is the location of the bin'd assets.
	assetPath string

	// manifestPath is the name of the manifest file.
	manifestPath string

	// faviconPath is the path to the favicon.
	faviconPath string

	// manifest is the map of the name of hashed paths -> original path
	manifest map[string]string

	// processed asset data
	assets map[string]*asset

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
		as.assetPath = path
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

// AssetFilterName sets the asset filter name used in the AssetSet.
func AssetFilterName(name string) AssetSetOption {
	return func(as *AssetSet) {
		as.assetFilterName = name
	}
}

// CsrfVariableName sets the csrf variable name used in the AssetSet.
func CsrfVariableName(name string) AssetSetOption {
	return func(as *AssetSet) {
		as.csrfVariableName = name
	}
}

// Csrf sets the func that generates a csrf token from the context for an
// AssetSet.
//
// Templates will have this value available to them via as {{ csrf }}.
func Csrf(f func(context.Context, *http.Request) string) AssetSetOption {
	return func(as *AssetSet) {
		as.csrf = f
	}
}

// NewAssetSet creates an asset set with the passed parameters.
func NewAssetSet(anFn assetNameFn, aFn assetFn, aiFn assetInfoFn, opts ...AssetSetOption) (*AssetSet, error) {
	as := &AssetSet{
		assetNameFn: anFn,
		assetFn:     aFn,
		assetInfoFn: aiFn,

		assetFilterName:  DefaultAssetFilterName,
		csrfVariableName: DefaultCsrfVariableName,

		csrf: nil,

		assetPath:       DefaultAssetPath,
		manifestPath:    DefaultManifestPath,
		templatesPath:   DefaultTemplatesPath,
		faviconPath:     DefaultFaviconPath,
		templatesSuffix: DefaultTemplatesSuffix,

		logger: log.Printf,
		ignore: []*regexp.Regexp{},

		manifest: make(map[string]string),
		assets:   make(map[string]*asset),
	}

	// apply options
	for _, o := range opts {
		o(as)
	}

	if !strings.HasSuffix(as.assetPath, "/") {
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

			// store data
			as.manifest[name] = hash
			as.assets[hash] = &asset{
				info:        &info,
				data:        &data,
				sha1:        fmt.Sprintf("%x", sha1.Sum(data)),
				contentType: as.contentType(name),
			}
		}
	}

	// create template storage
	as.templates = make(map[string]*pongo2.Template)

	// register asset filter
	pongo2.RegisterFilter(as.assetFilterName, as.Pongo2AssetFilter)

	// setup template set
	tplSet := pongo2.NewSet("", as)

	// loop over template assets and process
	for _, name := range anFn() {
		if strings.HasPrefix(name, as.templatesPath) && strings.HasSuffix(name, as.templatesSuffix) {
			n := name[len(as.templatesPath):]
			as.templates[n] = pongo2.Must(tplSet.FromFile(n))
		}
	}

	// format ignored
	ignoredStr := ""
	if ignoredCount > 0 {
		ignoredStr = fmt.Sprintf(", ignored: %d", ignoredCount)
	}

	as.logger("processed static assets (%d%s)", len(as.manifest), ignoredStr)
	as.logger("processed templates (%d)", len(as.templates))

	return as, nil
}

// staticHandler retrieves the static asset from the AssetSet, sending it to
// the http endpoint.
func (as *AssetSet) staticHandler(name string, res http.ResponseWriter, req *http.Request) {
	// grab info
	assetItem, ok := as.assets[name]
	if !ok {
		http.Error(res, http.StatusText(http.StatusNotFound), http.StatusNotFound)
		return
	}

	// grab modtime
	modtime := (*assetItem.info).ModTime()

	// check if-modified-since header, bail if present
	if t, err := time.Parse(http.TimeFormat, req.Header.Get("If-Modified-Since")); err == nil && modtime.Unix() <= t.Unix() {
		res.WriteHeader(http.StatusNotModified) // 304
		return
	}

	// check If-None-Match header, bail if present and match sha1
	if req.Header.Get("If-None-Match") == assetItem.sha1 {
		res.WriteHeader(http.StatusNotModified) // 304
		return
	}

	// set headers
	res.Header().Set("Content-Type", assetItem.contentType)
	res.Header().Set("Date", time.Now().Format(http.TimeFormat))

	// cache headers
	res.Header().Set("Cache-Control", "public, no-transform, max-age=31536000")
	res.Header().Set("Expires", time.Now().AddDate(1, 0, 0).Format(http.TimeFormat))
	res.Header().Set("Last-Modified", modtime.Format(http.TimeFormat))
	res.Header().Set("ETag", assetItem.sha1)

	// write data to response
	res.Write(*(assetItem.data))
}

// contentType returns the content type based on a file's name.
func (as *AssetSet) contentType(name string) string {
	// determine content type
	typ := "application/octet-stream"
	pos := strings.LastIndex(name, ".")
	if pos >= 0 {
		typ = mime.TypeByExtension(name[pos:])
	}

	return typ
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
	name, ok := as.manifest[val]
	if !ok {
		// asset not in manifest
		as.logger("asset %s not found in manifest", val)
		return pongo2.AsValue("NA"), nil
	}

	return pongo2.AsValue(as.assetPath + name), nil
}

// ExecuteTemplate executes a template from the asset with the passed context.
func (as *AssetSet) ExecuteTemplate(w io.Writer, name string, ctxt pongo2.Context) error {
	// load template
	tpl, ok := as.templates[name]
	if !ok {
		return fmt.Errorf("cannot load template %s", name)
	}

	// execute
	return tpl.ExecuteWriterUnbuffered(ctxt, w)
}

// TemplateHandler handles a template.
func (as *AssetSet) TemplateHandler(tplName string, ctxts ...pongo2.Context) func(context.Context, http.ResponseWriter, *http.Request) {
	// create final context for the handler
	final := pongo2.Context{}
	for _, ctxt := range ctxts {
		for k, v := range ctxt {
			final[k] = v
		}
	}

	return func(ctxt context.Context, res http.ResponseWriter, req *http.Request) {
		if as.csrf != nil {
			final[as.csrfVariableName] = as.csrf(ctxt, req)
		}

		err := as.ExecuteTemplate(res, tplName, final)
		if err != nil {
			http.Error(res, err.Error(), http.StatusInternalServerError)
		}
	}
}

// -----------------------------------------------------------------------
// Register registers the AssetSet to the provided mux.
func (as *AssetSet) Register(mux *goji.Mux) {
	// add favicon handler only if the favicon.ico is present in the path.
	if false {
		mux.HandleFuncC(pat.Get("/favicon.ico"), as.FaviconHandler)
	}

	mux.HandleFuncC(pat.Get(as.assetPath+"*"), as.StaticHandler)
}

func init() {
	mime.AddExtensionType("ico", "image/x-icon")
}
