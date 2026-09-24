package s3

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	awss3 "github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/rclone/rclone/fs"
	"github.com/rclone/rclone/fs/config/configmap"
	"github.com/rclone/rclone/fs/fshttp"
	"github.com/rclone/rclone/fs/hash"
	"github.com/rclone/rclone/fs/object"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newDirectFetchTestFs(ctx context.Context, t *testing.T, provider string, handler http.Handler) *Fs {
	t.Helper()
	return newDirectFetchTestFsWithConfig(ctx, t, provider, handler, nil)
}

func newDirectFetchTestFsWithConfig(ctx context.Context, t *testing.T, provider string, handler http.Handler, overrides configmap.Simple) *Fs {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	reg, err := fs.Find("s3")
	require.NoError(t, err)
	values := configmap.Simple{
		"provider":                provider,
		"endpoint":                server.URL,
		"region":                  "us-east-1",
		"access_key_id":           "test-access-key",
		"secret_access_key":       "test-secret-key",
		"session_token":           "",
		"env_auth":                "false",
		"role_arn":                "",
		"sts_endpoint":            "",
		"force_path_style":        "true",
		"use_accelerate_endpoint": "false",
		"no_check_bucket":         "true",
		"chunk_size":              "5Mi",
		"max_upload_parts":        "10000",
	}
	for key, value := range overrides {
		values[key] = value
	}
	m := fs.ConfigMap("s3", reg.Options, "direct-fetch-test", values)
	remote, err := NewFs(ctx, "direct-fetch-test", "bucket", m)
	require.NoError(t, err)
	return remote.(*Fs)
}

type directFetchWireCapture struct {
	request *http.Request
	body    []byte
}

func directFetchWireHandler(captures chan<- directFetchWireCapture, attempts *atomic.Int32) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		request := r.Clone(r.Context())
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		captures <- directFetchWireCapture{request: request, body: body}
		if attempts != nil && attempts.Add(1) == 1 {
			w.Header().Set("Content-Type", "application/xml")
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = io.WriteString(w, `<Error><Code>ServiceUnavailable</Code><Message>retry</Message></Error>`)
			return
		}
		w.Header().Set("ETag", `"etag"`)
	})
}

func directFetchAuthorizationSignature(t *testing.T, authorization string) string {
	t.Helper()
	_, signature, ok := strings.Cut(authorization, "Signature=")
	require.True(t, ok, "Authorization header has no signature: %q", authorization)
	return signature
}

func directFetchSignedHeaders(t *testing.T, authorization string) []string {
	t.Helper()
	_, rest, ok := strings.Cut(authorization, "SignedHeaders=")
	require.True(t, ok, "Authorization header has no signed headers: %q", authorization)
	signed, _, ok := strings.Cut(rest, ",")
	require.True(t, ok, "Authorization header has malformed signed headers: %q", authorization)
	return strings.Split(signed, ";")
}

func recomputeDirectFetchSignature(t *testing.T, request *http.Request, change func(*http.Request)) string {
	t.Helper()
	recomputed := request.Clone(context.Background())
	recomputed.URL.Scheme = "http"
	recomputed.URL.Host = request.Host
	recomputed.RequestURI = ""
	recomputed.Body = http.NoBody
	recomputed.Header.Del("Authorization")
	if change != nil {
		change(recomputed)
	}
	signingTime, err := time.Parse("20060102T150405Z", recomputed.Header.Get("X-Amz-Date"))
	require.NoError(t, err)
	payloadHash := recomputed.Header.Get("X-Amz-Content-Sha256")
	require.NotEmpty(t, payloadHash)
	err = v4.NewSigner().SignHTTP(context.Background(), aws.Credentials{
		AccessKeyID:     "test-access-key",
		SecretAccessKey: "test-secret-key",
	}, recomputed, payloadHash, "s3", "us-east-1", signingTime, func(options *v4.SignerOptions) {
		options.DisableURIPathEscaping = true
	})
	require.NoError(t, err)
	return directFetchAuthorizationSignature(t, recomputed.Header.Get("Authorization"))
}

func assertDirectFetchWireRequest(t *testing.T, capture directFetchWireCapture, sourceURL, byteRange string) {
	t.Helper()
	request := capture.request
	assert.Empty(t, capture.body)
	assert.Zero(t, request.ContentLength)
	assert.Equal(t, []string{"0"}, request.Header.Values("Content-Length"))
	assert.Empty(t, request.TransferEncoding)
	assert.Empty(t, request.Trailer)
	assert.Equal(t, sourceURL, request.Header.Get(directFetchSourceHeader))
	assert.Equal(t, byteRange, request.Header.Get("Range"))
	assert.Empty(t, request.Header.Get("Content-MD5"))
	assert.Empty(t, request.Header.Get("X-Amz-Sdk-Checksum-Algorithm"))
	assert.Empty(t, request.Header.Get("X-Amz-Trailer"))
	for header := range request.Header {
		assert.False(t, strings.HasPrefix(strings.ToLower(header), "x-amz-checksum-"), "unexpected checksum header %q", header)
	}

	authorization := request.Header.Get("Authorization")
	signedHeaders := directFetchSignedHeaders(t, authorization)
	assert.Contains(t, signedHeaders, directFetchSourceHeader)
	if byteRange == "" {
		assert.NotContains(t, signedHeaders, "range")
	} else {
		assert.Contains(t, signedHeaders, "range")
	}
	wireSignature := directFetchAuthorizationSignature(t, authorization)
	assert.Equal(t, wireSignature, recomputeDirectFetchSignature(t, request, nil))
	assert.NotEqual(t, wireSignature, recomputeDirectFetchSignature(t, request, func(changed *http.Request) {
		changed.Header.Set(directFetchSourceHeader, "https://changed.example/object")
	}))
	if byteRange != "" {
		assert.NotEqual(t, wireSignature, recomputeDirectFetchSignature(t, request, func(changed *http.Request) {
			changed.Header.Set("Range", "bytes=1-2")
		}))
	}
}

func TestDirectFetchWireOptionsSignEmptyRequestsAndStayLocal(t *testing.T) {
	ctx, ci := fs.AddConfig(context.Background())
	ci.LowLevelRetries = 1
	captures := make(chan directFetchWireCapture, 3)
	f := newDirectFetchTestFs(ctx, t, "Fastly", directFetchWireHandler(captures, nil))
	sourceURL := "https://source.example/a%20b?X-Amz-Signature=secret%2Bvalue"

	_, err := f.c.PutObject(ctx, &awss3.PutObjectInput{
		Bucket: aws.String("bucket"), Key: aws.String("key"),
		Body: nil, ContentLength: aws.Int64(0),
	}, directFetchOptions(sourceURL, ""))
	require.NoError(t, err)
	assertDirectFetchWireRequest(t, <-captures, sourceURL, "")

	_, err = f.c.UploadPart(ctx, &awss3.UploadPartInput{
		Bucket: aws.String("bucket"), Key: aws.String("key"), UploadId: aws.String("upload-1"), PartNumber: aws.Int32(1),
		Body: nil, ContentLength: aws.Int64(0),
	}, directFetchOptions(sourceURL, "bytes=10-19"))
	require.NoError(t, err)
	assertDirectFetchWireRequest(t, <-captures, sourceURL, "bytes=10-19")

	_, err = f.c.PutObject(ctx, &awss3.PutObjectInput{
		Bucket: aws.String("bucket"), Key: aws.String("ordinary"),
		Body: nil, ContentLength: aws.Int64(0),
	})
	require.NoError(t, err)
	ordinary := <-captures
	assert.Empty(t, ordinary.request.Header.Get(directFetchSourceHeader))
	assert.Empty(t, ordinary.request.Header.Get("Range"))
	assert.NotContains(t, directFetchSignedHeaders(t, ordinary.request.Header.Get("Authorization")), directFetchSourceHeader)
}

func TestDirectFetchWireSDKRetryPreservesSignedEmptyRequest(t *testing.T) {
	ctx, ci := fs.AddConfig(context.Background())
	ci.LowLevelRetries = 2
	captures := make(chan directFetchWireCapture, 2)
	var attempts atomic.Int32
	f := newDirectFetchTestFs(ctx, t, "Fastly", directFetchWireHandler(captures, &attempts))
	sourceURL := "https://source.example/retry?X-Amz-Signature=retry-secret"

	_, err := f.c.PutObject(ctx, &awss3.PutObjectInput{
		Bucket: aws.String("bucket"), Key: aws.String("key"),
		Body: nil, ContentLength: aws.Int64(0),
	}, directFetchOptions(sourceURL, ""))
	require.NoError(t, err)
	assert.Equal(t, int32(2), attempts.Load())
	assertDirectFetchWireRequest(t, <-captures, sourceURL, "")
	assertDirectFetchWireRequest(t, <-captures, sourceURL, "")
}

func TestDirectPublicLinkEligibility(t *testing.T) {
	ctx, _ := fs.AddConfig(context.Background())
	f := newDirectFetchTestFs(ctx, t, "AWS", http.NotFoundHandler())
	require.True(t, f.Features().PublicLinkIsDirect)
	tests := []struct {
		name   string
		change func(*Fs)
	}{
		{"other provider", func(f *Fs) { f.opt.Provider = "Other" }},
		{"decompress", func(f *Fs) { f.opt.Decompress = true }},
		{"might gzip", func(f *Fs) { f.opt.MightGzip.Value = true }},
		{"implicit decoding", func(f *Fs) { f.opt.UseAcceptEncodingGzip.Value = false }},
		{"download URL", func(f *Fs) { f.opt.DownloadURL = "https://cdn.example.invalid" }},
		{"requester pays", func(f *Fs) { f.opt.RequesterPays = true }},
		{"SSE-C algorithm", func(f *Fs) { f.opt.SSECustomerAlgorithm = "AES256" }},
		{"SSE-C raw key", func(f *Fs) { f.opt.SSECustomerKey = "key" }},
		{"SSE-C base64 key", func(f *Fs) { f.opt.SSECustomerKeyBase64 = "a2V5" }},
		{"SSE-C key MD5", func(f *Fs) { f.opt.SSECustomerKeyMD5 = "checksum" }},
		{"V2", func(f *Fs) { f.opt.V2Auth = true }},
		{"V2 region", func(f *Fs) { f.opt.Region = "other-v2-signature" }},
		{"versions", func(f *Fs) { f.opt.Versions = true }},
		{"version at", func(f *Fs) { f.opt.VersionAt = fs.Time(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)) }},
		{"directory bucket", func(f *Fs) { f.opt.DirectoryBucket = true }},
		{"no HEAD object", func(f *Fs) { f.opt.NoHeadObject = true }},
		{"logging client", func(f *Fs) { f.urlFetchLogSafe = false }},
		{"request-dependent client", func(f *Fs) { f.urlFetchRequestSafe = false }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			candidate := &Fs{opt: f.opt, urlFetchLogSafe: true, urlFetchRequestSafe: true}
			require.True(t, candidate.supportsDirectPublicLink())
			tt.change(candidate)
			assert.False(t, candidate.supportsDirectPublicLink())
		})
	}
	fastly := newDirectFetchTestFs(ctx, t, "Fastly", http.NotFoundHandler())
	assert.True(t, fastly.Features().PublicLinkIsDirect)
}

func TestDirectPublicLinkConstructor(t *testing.T) {
	for _, tt := range []struct {
		name     string
		provider string
		values   configmap.Simple
		config   func(*fs.ConfigInfo)
		want     bool
	}{
		{name: "AWS custom endpoint", provider: "AWS", want: true},
		{name: "empty header slice", provider: "AWS", config: func(ci *fs.ConfigInfo) { ci.Headers = []*fs.HTTPOption{} }, want: true},
		{name: "Fastly defaults", provider: "Fastly", want: true},
		{name: "Fastly explicit no gzip", provider: "Fastly", values: configmap.Simple{"might_gzip": "false"}, want: true},
		{name: "Fastly explicit might gzip", provider: "Fastly", values: configmap.Simple{"might_gzip": "true"}},
		{name: "Other explicit no gzip", provider: "Other", values: configmap.Simple{"might_gzip": "false"}},
		{name: "AWS explicit gzip", provider: "AWS", values: configmap.Simple{"might_gzip": "true"}},
		{name: "disabled feature", provider: "AWS", config: func(ci *fs.ConfigInfo) { ci.DisableFeatures = []string{"PublicLinkIsDirect"} }},
		{name: "dump headers", provider: "AWS", config: func(ci *fs.ConfigInfo) { ci.Dump = fs.DumpHeaders }},
		{name: "SDK logging", provider: "AWS", values: configmap.Simple{"sdk_log_mode": "Signing"}},
		{name: "custom headers", provider: "AWS", config: func(ci *fs.ConfigInfo) { ci.Headers = []*fs.HTTPOption{{Key: "X-Test", Value: "required"}} }},
		{name: "SSE-S3", provider: "AWS", values: configmap.Simple{"server_side_encryption": "AES256"}, want: true},
		{name: "SSE-KMS", provider: "AWS", values: configmap.Simple{"server_side_encryption": "aws:kms", "sse_kms_key_id": "test-key-id"}, want: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			ctx, ci := fs.AddConfig(context.Background())
			if tt.config != nil {
				tt.config(ci)
			}
			f := newDirectFetchTestFsWithConfig(ctx, t, tt.provider, http.NotFoundHandler(), tt.values)
			assert.Equal(t, tt.want, f.Features().PublicLinkIsDirect)
			assert.NotNil(t, f.Features().PublicLink)
			if tt.provider == "Fastly" {
				assert.Nil(t, f.Features().Copy)
				assert.True(t, f.opt.UseMultipartUploads.Value)
				assert.NotNil(t, f.Features().OpenChunkWriter)
			}
		})
	}
}

func TestDirectPublicLinkLoggingSnapshot(t *testing.T) {
	for _, tt := range []struct {
		name   string
		dump   fs.DumpFlags
		values configmap.Simple
	}{
		{name: "HTTP dump", dump: fs.DumpHeaders},
		{name: "SDK logging", values: configmap.Simple{"sdk_log_mode": "Signing"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			ctx, ci := fs.AddConfig(context.Background())
			ci.Dump = tt.dump
			f := newDirectFetchTestFsWithConfig(ctx, t, "AWS", http.NotFoundHandler(), tt.values)
			require.False(t, f.urlFetchLogSafe)
			require.True(t, f.urlFetchRequestSafe)
			ci.Dump = 0
			f.opt.SDKLogMode = 0
			if tt.values != nil {
				assert.NotZero(t, f.c.Options().ClientLogMode)
			}
			assert.False(t, f.urlFetchLogSafe)
			assert.False(t, f.supportsDirectPublicLink())
			assert.False(t, f.Features().PublicLinkIsDirect)
		})
	}
}

func TestDirectPublicLinkRequestSnapshot(t *testing.T) {
	ctx, ci := fs.AddConfig(context.Background())
	ci.LowLevelRetries = 1
	ci.Headers = []*fs.HTTPOption{{Key: "X-Test-Required", Value: "construction-value"}}
	f := newDirectFetchTestFs(ctx, t, "AWS", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodHead, r.Method)
		assert.Equal(t, "construction-value", r.Header.Get("X-Test-Required"))
		w.Header().Set("Content-Length", "1")
		w.Header().Set("Last-Modified", "Wed, 01 Jan 2025 00:00:00 GMT")
	}))
	require.True(t, f.urlFetchLogSafe)
	require.False(t, f.urlFetchRequestSafe)
	operationCtx, operationCI := fs.AddConfig(ctx)
	operationCI.Headers = nil
	ci.Headers = nil
	_, err := f.NewObject(operationCtx, "file")
	require.NoError(t, err)
	assert.False(t, f.urlFetchRequestSafe)
	assert.False(t, f.supportsDirectPublicLink())
	assert.False(t, f.Features().PublicLinkIsDirect)
}

func TestDirectPublicLinkClientCertificateSnapshot(t *testing.T) {
	// Use only httptest's synthetic certificate, never local credentials.
	server := httptest.NewTLSServer(http.NotFoundHandler())
	t.Cleanup(server.Close)
	cert := server.TLS.Certificates[0]
	key, err := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
	require.NoError(t, err)
	dir := t.TempDir()
	certPath, keyPath := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	require.NoError(t, os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]}), 0600))
	require.NoError(t, os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}), 0600))

	ctx, ci := fs.AddConfig(context.Background())
	ci.ClientCert, ci.ClientKey = certPath, keyPath
	f := newDirectFetchTestFs(ctx, t, "AWS", http.NotFoundHandler())
	require.True(t, f.urlFetchLogSafe)
	require.False(t, f.urlFetchRequestSafe)
	operationCtx, operationCI := fs.AddConfig(ctx)
	operationCI.ClientCert, operationCI.ClientKey = "", ""
	ci.ClientCert, ci.ClientKey = "", ""
	assert.Empty(t, fs.GetConfig(operationCtx).ClientCert)
	assert.Empty(t, fs.GetConfig(operationCtx).ClientKey)
	transport, ok := f.srv.Transport.(*fshttp.Transport)
	require.True(t, ok)
	assert.Len(t, transport.TLSClientConfig.Certificates, 1)
	assert.False(t, f.urlFetchRequestSafe)
	assert.False(t, f.supportsDirectPublicLink())
	assert.False(t, f.Features().PublicLinkIsDirect)
}

func TestDirectPublicLinkSafeSnapshot(t *testing.T) {
	ctx, ci := fs.AddConfig(context.Background())
	f := newDirectFetchTestFs(ctx, t, "AWS", http.NotFoundHandler())
	require.True(t, f.Features().PublicLinkIsDirect)
	ci.Dump = fs.DumpHeaders
	ci.Headers = []*fs.HTTPOption{{Key: "X-Test", Value: "later"}}
	ci.ClientCert, ci.ClientKey = "later-cert", "later-key"
	assert.True(t, f.urlFetchLogSafe)
	assert.True(t, f.urlFetchRequestSafe)
	assert.True(t, f.supportsDirectPublicLink())
}

func TestDirectPublicLinkConfiguredPresigning(t *testing.T) {
	for _, tt := range []struct {
		name     string
		provider string
		values   configmap.Simple
	}{
		{name: "AWS", provider: "AWS"},
		{name: "Fastly", provider: "Fastly", values: configmap.Simple{"might_gzip": "false"}},
		{name: "SSE-S3", provider: "AWS", values: configmap.Simple{"server_side_encryption": "AES256"}},
		{name: "SSE-KMS", provider: "AWS", values: configmap.Simple{"server_side_encryption": "aws:kms", "sse_kms_key_id": "test-key-id"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			ctx, ci := fs.AddConfig(context.Background())
			ci.LowLevelRetries = 1
			var requests atomic.Int32
			f := newDirectFetchTestFsWithConfig(ctx, t, tt.provider, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				assert.Equal(t, http.MethodHead, r.Method, "presigning must not fetch the source body or change sharing")
				w.Header().Set("Content-Length", "1")
				w.Header().Set("Last-Modified", "Wed, 01 Jan 2025 00:00:00 GMT")
			}), tt.values)
			require.True(t, f.Features().PublicLinkIsDirect)
			assert.Zero(t, requests.Load(), "a bucket-root constructor needs no object lookup")
			link, err := f.Features().PublicLink(ctx, "file", fs.Duration(24*time.Hour), false)
			require.NoError(t, err)
			u, err := url.Parse(link)
			require.NoError(t, err)
			assert.Equal(t, "/bucket/file", u.Path)
			assert.Equal(t, "86400", u.Query().Get("X-Amz-Expires"))
			assert.Equal(t, "host", u.Query().Get("X-Amz-SignedHeaders"))
			assert.Equal(t, int32(1), requests.Load())
		})
	}
}

type fetchSourceInfo struct {
	*object.StaticObjectInfo
}

func (s fetchSourceInfo) Hash(context.Context, hash.Type) (string, error) {
	panic("Direct Fetch must not request a source content hash")
}

type directFetchFailingCredentialsProvider struct {
	err error
}

func (p directFetchFailingCredentialsProvider) Retrieve(context.Context) (aws.Credentials, error) {
	return aws.Credentials{}, p.err
}

func directFetchSource(size int64, metadata fs.Metadata) fetchSourceInfo {
	return fetchSourceInfo{object.NewStaticObjectInfo("source.txt", time.Unix(10, 0), size, true, nil, nil).
		WithMimeType("text/source").WithMetadata(metadata)}
}

func directFetchSuccessHandler(captures chan<- directFetchWireCapture, headSize *int64) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		request := r.Clone(r.Context())
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		captures <- directFetchWireCapture{request: request, body: body}
		switch r.Method {
		case http.MethodPut:
			w.Header().Set("ETag", `"11111111111111111111111111111111"`)
			w.Header().Set("x-amz-version-id", "version-1")
		case http.MethodHead:
			if headSize != nil {
				w.Header().Set("Content-Length", strconv.FormatInt(*headSize, 10))
			}
			w.Header().Set("Last-Modified", "Wed, 01 Jan 2025 00:00:00 GMT")
			w.Header().Set("ETag", `"22222222222222222222222222222222"`)
			w.Header().Set("Content-Type", "application/head")
			w.Header().Set("X-Amz-Meta-Result", "from-head")
		default:
			w.WriteHeader(http.StatusBadRequest)
		}
	})
}

func TestDirectFetchSingle(t *testing.T) {
	ctx, ci := fs.AddConfig(context.Background())
	ci.LowLevelRetries = 1
	ci.Metadata = true
	headSize := int64(11)
	captures := make(chan directFetchWireCapture, 2)
	f := newDirectFetchTestFs(ctx, t, "Fastly", directFetchSuccessHandler(captures, &headSize))
	f.opt.Versions = true
	sourceURL := "https://source.example/a%2Fb?token=secret%2Bvalue"
	src := directFetchSource(7, fs.Metadata{"owner": "test"})

	got, err := f.ServerSideFetchURL(ctx, "target", sourceURL, src,
		&fs.HTTPOption{Key: "Cache-Control", Value: "private"})
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, int64(11), got.Size(), "the result must use the destination HEAD size")
	dst := got.(*Object)
	assert.Equal(t, "application/head", dst.mimeType)
	assert.Equal(t, "from-head", dst.meta["result"])
	assert.Equal(t, time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC), dst.lastModified)
	assert.Empty(t, dst.md5, "Fastly ETags are not content hashes")
	assert.Equal(t, "version-1", deref(dst.versionID))

	put := <-captures
	assert.Equal(t, http.MethodPut, put.request.Method)
	assert.Equal(t, "/bucket/target", put.request.URL.Path)
	assert.Equal(t, "private", put.request.Header.Get("Cache-Control"))
	assert.Equal(t, "test", put.request.Header.Get("X-Amz-Meta-Owner"))
	assert.NotEmpty(t, put.request.Header.Get("X-Amz-Meta-Mtime"))
	assertDirectFetchWireRequest(t, put, sourceURL, "")
	head := <-captures
	assert.Equal(t, http.MethodHead, head.request.Method)
	assert.Equal(t, "/bucket/target", head.request.URL.Path)
	assert.Equal(t, "version-1", head.request.URL.Query().Get("versionId"))
	assert.Empty(t, head.request.Header.Get(directFetchSourceHeader))
	assert.Empty(t, captures)
}

func TestDirectFetchBoundary(t *testing.T) {
	for _, tt := range []struct {
		name     string
		size     int64
		wantCopy bool
	}{
		{name: "unknown", size: -1},
		{name: "empty", size: 0, wantCopy: true},
		{name: "below cap", size: directFetchMaxSize - 1, wantCopy: true},
		{name: "at cap", size: directFetchMaxSize, wantCopy: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			ctx, ci := fs.AddConfig(context.Background())
			ci.LowLevelRetries = 1
			captures := make(chan directFetchWireCapture, 2)
			headSize := tt.size
			f := newDirectFetchTestFs(ctx, t, "Fastly", directFetchSuccessHandler(captures, &headSize))
			f.opt.UploadCutoff = fs.SizeSuffix(directFetchMaxSize + 1)
			got, err := f.ServerSideFetchURL(ctx, "target", "https://source.example/object", directFetchSource(tt.size, nil))
			if !tt.wantCopy {
				assert.Nil(t, got)
				assert.ErrorIs(t, err, fs.ErrorCantCopy)
				assert.Empty(t, captures)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, got)
			assert.Equal(t, tt.size, got.Size())
			assert.Equal(t, http.MethodPut, (<-captures).request.Method)
			assert.Equal(t, http.MethodHead, (<-captures).request.Method)
			assert.Empty(t, captures)
		})
	}
}

func TestDirectFetchPreflight(t *testing.T) {
	sourceURL := "https://source.example/object"
	src := directFetchSource(7, nil)

	t.Run("feature advertisement", func(t *testing.T) {
		for _, tt := range []struct {
			name     string
			provider string
			values   configmap.Simple
			config   func(*fs.ConfigInfo)
			want     bool
		}{
			{name: "Fastly", provider: "Fastly", want: true},
			{name: "AWS", provider: "AWS"},
			{name: "Other", provider: "Other"},
			{name: "disabled", provider: "Fastly", config: func(ci *fs.ConfigInfo) { ci.DisableFeatures = []string{"ServerSideFetchURL"} }},
			{name: "construction HTTP logging", provider: "Fastly", config: func(ci *fs.ConfigInfo) { ci.Dump = fs.DumpHeaders }},
			{name: "construction SDK logging", provider: "Fastly", values: configmap.Simple{"sdk_log_mode": "Signing"}},
			{name: "construction headers", provider: "Fastly", config: func(ci *fs.ConfigInfo) {
				ci.Headers = []*fs.HTTPOption{{Key: "X-Required", Value: "value"}}
			}},
		} {
			t.Run(tt.name, func(t *testing.T) {
				ctx, ci := fs.AddConfig(context.Background())
				if tt.config != nil {
					tt.config(ci)
				}
				f := newDirectFetchTestFsWithConfig(ctx, t, tt.provider, http.NotFoundHandler(), tt.values)
				assert.Equal(t, tt.want, f.Features().ServerSideFetchURL != nil)
			})
		}
	})

	t.Run("unsupported destinations and HEAD modes", func(t *testing.T) {
		for _, tt := range []struct {
			name     string
			provider string
			change   func(*Fs)
		}{
			{name: "AWS", provider: "AWS"},
			{name: "Other", provider: "Other"},
			{name: "no head", provider: "Fastly", change: func(f *Fs) { f.opt.NoHead = true }},
			{name: "no head object", provider: "Fastly", change: func(f *Fs) { f.opt.NoHeadObject = true }},
		} {
			t.Run(tt.name, func(t *testing.T) {
				ctx, _ := fs.AddConfig(context.Background())
				var requests atomic.Int32
				f := newDirectFetchTestFs(ctx, t, tt.provider, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
					requests.Add(1)
				}))
				if tt.change != nil {
					tt.change(f)
				}
				got, err := f.ServerSideFetchURL(ctx, "target", sourceURL, src)
				assert.Nil(t, got)
				assert.ErrorIs(t, err, fs.ErrorCantCopy)
				assert.Zero(t, requests.Load())
			})
		}
	})

	t.Run("immutable construction exclusions survive a changed context", func(t *testing.T) {
		for _, tt := range []struct {
			name   string
			config func(*fs.ConfigInfo)
		}{
			{name: "logging", config: func(ci *fs.ConfigInfo) { ci.Dump = fs.DumpHeaders }},
			{name: "headers", config: func(ci *fs.ConfigInfo) {
				ci.Headers = []*fs.HTTPOption{{Key: "X-Required", Value: "construction"}}
			}},
		} {
			t.Run(tt.name, func(t *testing.T) {
				ctx, ci := fs.AddConfig(context.Background())
				tt.config(ci)
				var requests atomic.Int32
				f := newDirectFetchTestFs(ctx, t, "Fastly", http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
					requests.Add(1)
				}))
				opCtx, opCI := fs.AddConfig(context.Background())
				opCI.Dump = 0
				opCI.Headers = nil
				opCI.ClientCert, opCI.ClientKey = "", ""
				got, err := f.ServerSideFetchURL(opCtx, "target", sourceURL, src)
				assert.Nil(t, got)
				assert.ErrorIs(t, err, fs.ErrorCantCopy)
				assert.Zero(t, requests.Load())
			})
		}
	})

	t.Run("current operation context exclusions", func(t *testing.T) {
		for _, tt := range []struct {
			name   string
			config func(*fs.ConfigInfo)
		}{
			{name: "logging", config: func(ci *fs.ConfigInfo) { ci.Dump = fs.DumpHeaders }},
			{name: "headers", config: func(ci *fs.ConfigInfo) {
				ci.Headers = []*fs.HTTPOption{{Key: "X-Later", Value: "operation"}}
			}},
			{name: "client certificate", config: func(ci *fs.ConfigInfo) { ci.ClientCert = "later-cert" }},
			{name: "client key", config: func(ci *fs.ConfigInfo) { ci.ClientKey = "later-key" }},
		} {
			t.Run(tt.name, func(t *testing.T) {
				ctx, _ := fs.AddConfig(context.Background())
				var requests atomic.Int32
				f := newDirectFetchTestFs(ctx, t, "Fastly", http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
					requests.Add(1)
				}))
				opCtx, opCI := fs.AddConfig(ctx)
				tt.config(opCI)
				got, err := f.ServerSideFetchURL(opCtx, "target", sourceURL, src)
				assert.Nil(t, got)
				assert.ErrorIs(t, err, fs.ErrorCantCopy)
				assert.Zero(t, requests.Load())
			})
		}
	})

	t.Run("uppercase HTTP source URL is preserved", func(t *testing.T) {
		ctx, ci := fs.AddConfig(context.Background())
		ci.LowLevelRetries = 1
		headSize := int64(7)
		captures := make(chan directFetchWireCapture, 2)
		f := newDirectFetchTestFs(ctx, t, "Fastly", directFetchSuccessHandler(captures, &headSize))
		got, err := f.ServerSideFetchURL(ctx, "target", "HTTPS://source.example/object", src)
		require.NoError(t, err)
		require.NotNil(t, got)
		assert.Equal(t, "HTTPS://source.example/object", (<-captures).request.Header.Get(directFetchSourceHeader))
		assert.Equal(t, http.MethodHead, (<-captures).request.Method)
	})

	t.Run("invalid source URLs", func(t *testing.T) {
		for _, sourceURL := range []string{
			"", "://missing-scheme", "ftp://source.example/object", "https:///missing-host",
			"https://user:password@source.example/object", "https://source.example/object#fragment",
		} {
			t.Run(strings.ReplaceAll(sourceURL, "/", "_"), func(t *testing.T) {
				ctx, _ := fs.AddConfig(context.Background())
				var requests atomic.Int32
				f := newDirectFetchTestFs(ctx, t, "Fastly", http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
					requests.Add(1)
				}))
				got, err := f.ServerSideFetchURL(ctx, "target", sourceURL, src)
				assert.Nil(t, got)
				assert.ErrorIs(t, err, fs.ErrorCantCopy)
				assert.Zero(t, requests.Load())
			})
		}
	})

	t.Run("canceled context", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		var requests atomic.Int32
		f := newDirectFetchTestFs(context.Background(), t, "Fastly", http.HandlerFunc(func(http.ResponseWriter, *http.Request) { requests.Add(1) }))
		got, err := f.ServerSideFetchURL(ctx, "target", sourceURL, src)
		assert.Nil(t, got)
		assert.ErrorIs(t, err, context.Canceled)
		assert.NotErrorIs(t, err, fs.ErrorCantCopy)
		assert.Zero(t, requests.Load())
	})

	t.Run("configuration and credential errors do not authorize fallback", func(t *testing.T) {
		t.Run("version at", func(t *testing.T) {
			ctx, _ := fs.AddConfig(context.Background())
			var requests atomic.Int32
			f := newDirectFetchTestFs(ctx, t, "Fastly", http.HandlerFunc(func(http.ResponseWriter, *http.Request) { requests.Add(1) }))
			f.opt.VersionAt = fs.Time(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC))
			got, err := f.ServerSideFetchURL(ctx, "target", sourceURL, src)
			assert.Nil(t, got)
			assert.ErrorIs(t, err, errNotWithVersionAt)
			assert.NotErrorIs(t, err, fs.ErrorCantCopy)
			assert.Zero(t, requests.Load())
		})
		t.Run("V2 signing", func(t *testing.T) {
			ctx, _ := fs.AddConfig(context.Background())
			var requests atomic.Int32
			f := newDirectFetchTestFsWithConfig(ctx, t, "Fastly", http.HandlerFunc(func(http.ResponseWriter, *http.Request) { requests.Add(1) }), configmap.Simple{"v2_auth": "true"})
			got, err := f.ServerSideFetchURL(ctx, "target", sourceURL, src)
			assert.Nil(t, got)
			assert.Error(t, err)
			assert.NotErrorIs(t, err, fs.ErrorCantCopy)
			assert.Zero(t, requests.Load())
		})
		t.Run("anonymous", func(t *testing.T) {
			ctx, _ := fs.AddConfig(context.Background())
			var requests atomic.Int32
			f := newDirectFetchTestFsWithConfig(ctx, t, "Fastly", http.HandlerFunc(func(http.ResponseWriter, *http.Request) { requests.Add(1) }), configmap.Simple{
				"access_key_id": "", "secret_access_key": "",
			})
			got, err := f.ServerSideFetchURL(ctx, "target", sourceURL, src)
			assert.Nil(t, got)
			assert.Error(t, err)
			assert.NotErrorIs(t, err, fs.ErrorCantCopy)
			assert.Zero(t, requests.Load())
		})
		credentialCause := errors.New("credential fixture failed")
		for _, tt := range []struct {
			name        string
			credentials aws.CredentialsProvider
			cause       error
		}{
			{name: "nil credential provider"},
			{name: "credentials without keys", credentials: directFetchFailingCredentialsProvider{}},
			{name: "credential provider failure", credentials: directFetchFailingCredentialsProvider{err: credentialCause}, cause: credentialCause},
		} {
			t.Run(tt.name, func(t *testing.T) {
				ctx, _ := fs.AddConfig(context.Background())
				var requests atomic.Int32
				f := newDirectFetchTestFs(ctx, t, "Fastly", http.HandlerFunc(func(http.ResponseWriter, *http.Request) { requests.Add(1) }))
				options := f.c.Options()
				options.Credentials = tt.credentials
				f.c = awss3.New(options)
				got, err := f.ServerSideFetchURL(ctx, "target", sourceURL, src)
				assert.Nil(t, got)
				assert.Error(t, err)
				if tt.cause != nil {
					assert.ErrorIs(t, err, tt.cause)
				}
				assert.NotErrorIs(t, err, fs.ErrorCantCopy)
				assert.Zero(t, requests.Load())
			})
		}
	})

	t.Run("Object Lock", func(t *testing.T) {
		for _, tt := range []struct {
			name     string
			values   configmap.Simple
			metadata fs.Metadata
			config   func(*fs.ConfigInfo)
		}{
			{name: "set after upload", values: configmap.Simple{"object_lock_set_after_upload": "true"}},
			{name: "request option", values: configmap.Simple{"object_lock_mode": "GOVERNANCE"}},
			{name: "source metadata", values: configmap.Simple{"object_lock_mode": "copy"}, metadata: fs.Metadata{"object-lock-mode": "GOVERNANCE"}, config: func(ci *fs.ConfigInfo) { ci.Metadata = true }},
		} {
			t.Run(tt.name, func(t *testing.T) {
				ctx, ci := fs.AddConfig(context.Background())
				if tt.config != nil {
					tt.config(ci)
				}
				var requests atomic.Int32
				f := newDirectFetchTestFsWithConfig(ctx, t, "Fastly", http.HandlerFunc(func(http.ResponseWriter, *http.Request) { requests.Add(1) }), tt.values)
				got, err := f.ServerSideFetchURL(ctx, "target", sourceURL, directFetchSource(7, tt.metadata))
				assert.Nil(t, got)
				assert.ErrorIs(t, err, fs.ErrorCantCopy)
				assert.Zero(t, requests.Load())
			})
		}
	})
}

func TestDirectFetchMapperProcess(t *testing.T) {
	if os.Getenv("RCLONE_FETCH_MAPPER_HELPER") != "1" {
		return
	}
	var item struct {
		Metadata fs.Metadata
	}
	if err := json.NewDecoder(os.Stdin).Decode(&item); err != nil {
		os.Exit(2)
	}
	if item.Metadata == nil {
		item.Metadata = make(fs.Metadata)
	}
	item.Metadata["mapped"] = "yes"
	if err := json.NewEncoder(os.Stdout).Encode(item); err != nil {
		os.Exit(3)
	}
	os.Exit(0)
}

func TestDirectFetchMetadata(t *testing.T) {
	ctx, ci := fs.AddConfig(context.Background())
	ci.LowLevelRetries = 1
	ci.Metadata = true
	t.Setenv("RCLONE_FETCH_MAPPER_HELPER", "1")
	exe, err := os.Executable()
	require.NoError(t, err)
	ci.MetadataMapper = fs.SpaceSepList{exe, "-test.run=^TestDirectFetchMapperProcess$"}
	headSize := int64(7)
	captures := make(chan directFetchWireCapture, 2)
	f := newDirectFetchTestFsWithConfig(ctx, t, "Fastly", directFetchSuccessHandler(captures, &headSize), configmap.Simple{
		"server_side_encryption": "AES256",
		"storage_class":          "STANDARD_IA",
	})
	metadataMtime := time.Date(2025, 2, 3, 4, 5, 6, 700, time.UTC)
	src := directFetchSource(7, fs.Metadata{
		"owner":             "source",
		"source-only":       "kept",
		"option-precedence": "source",
		"cache-control":     "source-cache",
		"mtime":             metadataMtime.Format(time.RFC3339Nano),
	})

	got, err := f.ServerSideFetchURL(ctx, "target.txt", "https://source.example/object", src,
		fs.MetadataOption(fs.Metadata{"owner": "metadata-option", "option-only": "kept", "option-precedence": "metadata-option"}),
		&fs.HTTPOption{Key: "X-Amz-Meta-Owner", Value: "upload-header"},
		&fs.HTTPOption{Key: "Cache-Control", Value: "upload-cache"},
		&fs.HTTPOption{Key: "If-Match", Value: `"old"`},
		&fs.HTTPOption{Key: "If-None-Match", Value: `"other"`})
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Nil(t, got.(*Object).versionID, "ordinary mode must not retain the returned version ID")
	put := <-captures
	assert.Equal(t, "kept", put.request.Header.Get("X-Amz-Meta-Source-Only"))
	assert.Equal(t, "kept", put.request.Header.Get("X-Amz-Meta-Option-Only"))
	assert.Equal(t, "metadata-option", put.request.Header.Get("X-Amz-Meta-Option-Precedence"))
	assert.Equal(t, "upload-header", put.request.Header.Get("X-Amz-Meta-Owner"))
	assert.Equal(t, "yes", put.request.Header.Get("X-Amz-Meta-Mapped"))
	assert.Equal(t, "1738555506.0000007", put.request.Header.Get("X-Amz-Meta-Mtime"))
	assert.Equal(t, "upload-cache", put.request.Header.Get("Cache-Control"))
	assert.Equal(t, "text/source", put.request.Header.Get("Content-Type"))
	assert.Equal(t, "AES256", put.request.Header.Get("X-Amz-Server-Side-Encryption"))
	assert.Equal(t, "STANDARD_IA", put.request.Header.Get("X-Amz-Storage-Class"))
	assert.Equal(t, `"old"`, put.request.Header.Get("If-Match"))
	assert.Equal(t, `"other"`, put.request.Header.Get("If-None-Match"))
	assert.Empty(t, put.request.Header.Get("X-Amz-Meta-"+metaMD5Hash))
	assertDirectFetchWireRequest(t, put, "https://source.example/object", "")
	assert.Equal(t, http.MethodHead, (<-captures).request.Method)
}

func TestDirectFetchResultErrors(t *testing.T) {
	src := directFetchSource(7, nil)
	sourceURL := "https://source.example/object?token=secret"
	for _, tt := range []struct {
		name             string
		handler          http.Handler
		wantCantCopy     bool
		wantRequestCount int32
	}{
		{
			name: "source status may fall back",
			handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/xml")
				w.Header().Set(directFetchErrorHeader, "DirectFetchSourceStatus 403")
				w.WriteHeader(http.StatusBadRequest)
				_, _ = io.WriteString(w, `<Error><Code>DirectFetchSourceStatus</Code><Message>403</Message></Error>`)
			}),
			wantCantCopy: true, wantRequestCount: 1,
		},
		{
			name: "destination error is final",
			handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/xml")
				w.WriteHeader(http.StatusForbidden)
				_, _ = io.WriteString(w, `<Error><Code>AccessDenied</Code><Message>destination denied</Message></Error>`)
			}),
			wantRequestCount: 1,
		},
		{
			name:             "successful put without ETag",
			handler:          http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}),
			wantRequestCount: 1,
		},
		{
			name: "HEAD failure after successful put",
			handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodPut {
					w.Header().Set("ETag", `"etag"`)
					return
				}
				w.Header().Set("Content-Type", "application/xml")
				w.WriteHeader(http.StatusBadRequest)
				_, _ = io.WriteString(w, `<Error><Code>InvalidRequest</Code><Message>HEAD failed</Message></Error>`)
			}),
			wantRequestCount: 2,
		},
		{
			name: "HEAD missing size",
			handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodPut {
					w.Header().Set("ETag", `"etag"`)
					return
				}
				w.Header().Set("Last-Modified", "Wed, 01 Jan 2025 00:00:00 GMT")
			}),
			wantRequestCount: 2,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			ctx, ci := fs.AddConfig(context.Background())
			ci.LowLevelRetries = 1
			var requests atomic.Int32
			f := newDirectFetchTestFs(ctx, t, "Fastly", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				tt.handler.ServeHTTP(w, r)
			}))
			got, err := f.ServerSideFetchURL(ctx, "target", sourceURL, src)
			assert.Nil(t, got)
			assert.Error(t, err)
			assert.Equal(t, tt.wantCantCopy, errors.Is(err, fs.ErrorCantCopy))
			assert.Equal(t, tt.wantRequestCount, requests.Load())
			assert.NotContains(t, err.Error(), "token=secret")
		})
	}
}
