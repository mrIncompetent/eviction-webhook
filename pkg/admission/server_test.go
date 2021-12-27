package admission

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest"
	admissionv1 "k8s.io/api/admission/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"

	loghelper "github.com/mrincompetent/eviction-webhook/pkg/log"
)

func TestServer_HandleV1AdmissionReview(t *testing.T) {
	emptySuccessfulHandler := func(ctx context.Context, logger *zap.Logger, request *admissionv1.AdmissionRequest) (*admissionv1.AdmissionResponse, error) {
		return &admissionv1.AdmissionResponse{
			Allowed: true,
		}, nil
	}
	emptyAddmissionReview := &admissionv1.AdmissionReview{
		Request: &admissionv1.AdmissionRequest{
			UID: "test",
		},
	}
	tests := []struct {
		name                    string
		handler                 Handler
		expectedStatusCode      int
		admissionReview         *admissionv1.AdmissionReview
		expectedAdmissionResult bool
		contentType             string
		acceptType              string
		expectedError           string
	}{
		{
			name:                    "successful empty handler - JSON",
			expectedStatusCode:      http.StatusOK,
			handler:                 emptySuccessfulHandler,
			admissionReview:         emptyAddmissionReview,
			expectedAdmissionResult: true,
			contentType:             runtime.ContentTypeJSON,
			acceptType:              runtime.ContentTypeJSON,
		},
		{
			name:                    "successful empty handler - YAML",
			expectedStatusCode:      http.StatusOK,
			handler:                 emptySuccessfulHandler,
			admissionReview:         emptyAddmissionReview,
			expectedAdmissionResult: true,
			contentType:             runtime.ContentTypeYAML,
			acceptType:              runtime.ContentTypeYAML,
		},
		{
			name:                    "successful empty handler - protobuf",
			expectedStatusCode:      http.StatusOK,
			handler:                 emptySuccessfulHandler,
			admissionReview:         emptyAddmissionReview,
			expectedAdmissionResult: true,
			contentType:             runtime.ContentTypeProtobuf,
			acceptType:              runtime.ContentTypeProtobuf,
		},
		{
			name:               "missing admission review request",
			expectedStatusCode: http.StatusBadRequest,
			handler:            emptySuccessfulHandler,
			admissionReview:    &admissionv1.AdmissionReview{},
			contentType:        runtime.ContentTypeJSON,
			acceptType:         runtime.ContentTypeJSON,
			expectedError:      "no request defined in admission review",
		},
		{
			name:                    "invalid accept type",
			expectedStatusCode:      http.StatusInternalServerError,
			handler:                 emptySuccessfulHandler,
			admissionReview:         emptyAddmissionReview,
			expectedAdmissionResult: true,
			contentType:             runtime.ContentTypeJSON,
			acceptType:              "invalid",
			expectedError:           "failed to encode response: unsupported media type \"invalid\"",
		},
		{
			name: "failed handler",
			handler: func(ctx context.Context, logger *zap.Logger, request *admissionv1.AdmissionRequest) (*admissionv1.AdmissionResponse, error) {
				return nil, errors.New("failed")
			},
			expectedStatusCode: http.StatusInternalServerError,
			admissionReview:    emptyAddmissionReview,
			contentType:        runtime.ContentTypeJSON,
			acceptType:         runtime.ContentTypeJSON,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			scheme := runtime.NewScheme()
			utilruntime.Must(admissionv1.AddToScheme(scheme))

			server := NewServer(scheme)
			httpHandler := server.HandleV1AdmissionReview(test.handler)

			httpServer := httptest.NewServer(loghelper.RequestLogMiddleware(zaptest.NewLogger(t), httpHandler))
			defer httpServer.Close()
			httpServer.Client()

			buf := &bytes.Buffer{}
			serializerInfo, err := serializerInfoForMediaType(server.codecs, test.contentType)
			require.NoError(t, err)

			require.NoError(t, serializerInfo.Serializer.Encode(test.admissionReview, buf))
			t.Log(buf.String())

			ctx := loghelper.ToContext(context.Background(), zaptest.NewLogger(t))
			request, err := http.NewRequestWithContext(ctx, http.MethodPost, httpServer.URL, buf)
			require.NoError(t, err)

			request.Header.Set("Content-Type", test.contentType)
			request.Header.Set("Accept", test.acceptType)

			resp, err := httpServer.Client().Do(request)
			require.NoError(t, err)
			defer resp.Body.Close()

			responseBody, err := io.ReadAll(resp.Body)
			require.NoError(t, err)
			t.Log(string(responseBody))

			// check response
			assert.Equal(t, test.expectedStatusCode, resp.StatusCode)

			if test.expectedStatusCode == http.StatusOK {
				admissionReview := &admissionv1.AdmissionReview{}

				_, _, err := serializerInfo.Serializer.Decode(responseBody, nil, admissionReview)
				require.NoError(t, err)

				assert.Equal(t, test.expectedAdmissionResult, admissionReview.Response.Allowed)
			} else {
				assert.Contains(t, string(responseBody), test.expectedError)
			}
		})
	}
}
