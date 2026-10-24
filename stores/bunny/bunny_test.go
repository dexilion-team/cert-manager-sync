package bunny

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/robertlestak/cert-manager-sync/pkg/state"
	"github.com/robertlestak/cert-manager-sync/pkg/tlssecret"
	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

type recordedRequest struct {
	Method    string
	Path      string
	AccessKey string
	Body      map[string]string
}

// fakeBunny swaps apiBaseURL for an httptest server answering every request
// with status, and the kube client for one holding a bunny-creds secret.
func fakeBunny(t *testing.T, status int, respBody string) *[]recordedRequest {
	t.Helper()
	var mu sync.Mutex
	reqs := []recordedRequest{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := map[string]string{}
		_ = json.NewDecoder(r.Body).Decode(&body)
		mu.Lock()
		reqs = append(reqs, recordedRequest{
			Method:    r.Method,
			Path:      r.URL.Path,
			AccessKey: r.Header.Get("AccessKey"),
			Body:      body,
		})
		mu.Unlock()
		w.WriteHeader(status)
		_, _ = w.Write([]byte(respBody))
	}))
	t.Cleanup(srv.Close)

	oldURL := apiBaseURL
	apiBaseURL = srv.URL
	t.Cleanup(func() { apiBaseURL = oldURL })

	oldClient := state.KubeClient
	state.KubeClient = fake.NewSimpleClientset(&corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "bunny-creds", Namespace: "cert-manager"},
		Data:       map[string][]byte{"api_key": []byte("secret-key")},
	})
	t.Cleanup(func() { state.KubeClient = oldClient })
	return &reqs
}

func TestBunnyFromConfig(t *testing.T) {
	s := &BunnyStore{}

	err := s.FromConfig(tlssecret.GenericSecretSyncConfig{
		Config: map[string]string{
			"secret-name":  "shared/bunny-creds",
			"pull-zone-id": "12345",
			"hostname":     "cdn.example.com, static.example.com,",
		},
	})

	assert.NoError(t, err)
	assert.Equal(t, "bunny-creds", s.SecretName)
	assert.Equal(t, "shared", s.SecretNamespace)
	assert.Equal(t, "12345", s.PullZoneId)
	assert.Equal(t, []string{"cdn.example.com", "static.example.com"}, s.Hostnames)
}

func TestBunnyValidate(t *testing.T) {
	cases := []struct {
		name string
		s    *BunnyStore
	}{
		{name: "missing secret name", s: &BunnyStore{PullZoneId: "1", Hostnames: []string{"a"}}},
		{name: "missing pull zone", s: &BunnyStore{SecretName: "n", Hostnames: []string{"a"}}},
		{name: "non-numeric pull zone", s: &BunnyStore{SecretName: "n", PullZoneId: "1/../2", Hostnames: []string{"a"}}},
		{name: "missing hostname", s: &BunnyStore{SecretName: "n", PullZoneId: "1"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Error(t, tc.s.validate())
		})
	}
	assert.NoError(t, (&BunnyStore{SecretName: "n", PullZoneId: "1", Hostnames: []string{"a"}}).validate())
}

func TestBunnySync(t *testing.T) {
	reqs := fakeBunny(t, http.StatusNoContent, "")
	s := &BunnyStore{}
	assert.NoError(t, s.FromConfig(tlssecret.GenericSecretSyncConfig{
		Config: map[string]string{
			"secret-name":  "bunny-creds",
			"pull-zone-id": "42",
			"hostname":     "cdn.example.com,static.example.com",
		},
	}))
	cert := &tlssecret.Certificate{
		SecretName:  "source",
		Namespace:   "cert-manager",
		Certificate: []byte("CERT\n"),
		Key:         []byte("KEY\n"),
	}

	updates, err := s.Sync(cert)

	assert.NoError(t, err)
	assert.Nil(t, updates)
	assert.Equal(t, "cert-manager", s.SecretNamespace)
	if assert.Len(t, *reqs, 2) {
		for i, h := range []string{"cdn.example.com", "static.example.com"} {
			r := (*reqs)[i]
			assert.Equal(t, http.MethodPost, r.Method)
			assert.Equal(t, "/pullzone/42/addCertificate", r.Path)
			assert.Equal(t, "secret-key", r.AccessKey)
			assert.Equal(t, h, r.Body["Hostname"])
			assert.Equal(t, base64.StdEncoding.EncodeToString(cert.FullChain()), r.Body["Certificate"])
			assert.Equal(t, base64.StdEncoding.EncodeToString(cert.Key), r.Body["CertificateKey"])
		}
	}
}

func TestBunnySyncSurfacesApiError(t *testing.T) {
	fakeBunny(t, http.StatusBadRequest, `{"ErrorKey":"pullzone.hostname_not_found","Field":"Hostname","Message":"The hostname was not found"}`)
	s := &BunnyStore{SecretName: "bunny-creds", PullZoneId: "42", Hostnames: []string{"cdn.example.com"}}

	_, err := s.Sync(&tlssecret.Certificate{Namespace: "cert-manager"})

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "The hostname was not found")
	assert.Contains(t, err.Error(), "cdn.example.com")
}

func TestBunnySyncSecretNamespaceDefaulting(t *testing.T) {
	oldClient := state.KubeClient
	state.KubeClient = fake.NewSimpleClientset()
	t.Cleanup(func() { state.KubeClient = oldClient })

	s := &BunnyStore{SecretName: "bunny-creds", PullZoneId: "42", Hostnames: []string{"cdn.example.com"}}
	_, err := s.Sync(&tlssecret.Certificate{Namespace: "cert-manager"})

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "cert-manager/bunny-creds")
}

func TestBunnyDelete(t *testing.T) {
	reqs := fakeBunny(t, http.StatusNoContent, "")
	s := &BunnyStore{SecretName: "bunny-creds", SecretNamespace: "cert-manager", PullZoneId: "42", Hostnames: []string{"cdn.example.com"}}

	assert.NoError(t, s.Delete(context.Background()))
	if assert.Len(t, *reqs, 1) {
		r := (*reqs)[0]
		assert.Equal(t, http.MethodDelete, r.Method)
		assert.Equal(t, "/pullzone/42/removeCertificate", r.Path)
		assert.Equal(t, "cdn.example.com", r.Body["Hostname"])
	}
}

func TestBunnyDelete_NotFoundIsSuccess(t *testing.T) {
	fakeBunny(t, http.StatusNotFound, "")
	s := &BunnyStore{SecretName: "bunny-creds", SecretNamespace: "cert-manager", PullZoneId: "42", Hostnames: []string{"cdn.example.com"}}

	assert.NoError(t, s.Delete(context.Background()))
}

func TestBunnyDelete_ErrorsOnFailure(t *testing.T) {
	fakeBunny(t, http.StatusInternalServerError, "boom")
	s := &BunnyStore{SecretName: "bunny-creds", SecretNamespace: "cert-manager", PullZoneId: "42", Hostnames: []string{"cdn.example.com"}}

	err := s.Delete(context.Background())

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "boom")
}

func TestBunnyDelete_RequiresConfig(t *testing.T) {
	s := &BunnyStore{SecretName: "bunny-creds", SecretNamespace: "cert-manager"}

	assert.Error(t, s.Delete(context.Background()))
}
