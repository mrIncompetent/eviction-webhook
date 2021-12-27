package http

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"

	loghelper "github.com/mrincompetent/eviction-webhook/pkg/log"
)

type HandlerResult string

const (
	HandlerResultContextTimeout HandlerResult = "context-timeout"
	HandlerResultTick           HandlerResult = "tick"
)

func TestRequestAwareTimeoutMiddleware(t *testing.T) {
	tests := []struct {
		name                  string
		requestTimeout        string
		middlewareTimeout     time.Duration
		requestDuration       time.Duration
		expectedHandlerResult HandlerResult
		expectedStatusCode    int
		expectedResponseBody  string
	}{
		{
			name:                  "default timeout gets applied to a long running request",
			requestTimeout:        "",
			requestDuration:       100 * time.Millisecond,
			middlewareTimeout:     10 * time.Millisecond,
			expectedHandlerResult: HandlerResultContextTimeout,
			expectedStatusCode:    http.StatusServiceUnavailable,
			expectedResponseBody:  "failed to serve the request within the timeout of 10ms",
		},
		{
			name:                  "default timeout gets applied to a long running request with invalid timeout query parameter",
			requestTimeout:        "invalid-time",
			requestDuration:       100 * time.Millisecond,
			middlewareTimeout:     10 * time.Millisecond,
			expectedHandlerResult: HandlerResultContextTimeout,
			expectedStatusCode:    http.StatusServiceUnavailable,
			expectedResponseBody:  "failed to serve the request within the timeout of 10ms",
		},
		{
			name:                  "timeout from request gets applied to a long running request",
			requestTimeout:        (10 * time.Millisecond).String(),
			requestDuration:       100 * time.Millisecond,
			middlewareTimeout:     200 * time.Millisecond,
			expectedHandlerResult: HandlerResultContextTimeout,
			expectedStatusCode:    http.StatusServiceUnavailable,
			expectedResponseBody:  "failed to serve the request within the timeout of 10ms",
		},
		{
			name:                  "timeout from request gets applied to a short running request",
			requestTimeout:        (100 * time.Millisecond).String(),
			requestDuration:       5 * time.Millisecond,
			middlewareTimeout:     200 * time.Millisecond,
			expectedHandlerResult: HandlerResultTick,
			expectedStatusCode:    http.StatusOK,
			expectedResponseBody:  "OK",
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			//t.Parallel()

			handlerResultChan := make(chan HandlerResult, 1)
			defer close(handlerResultChan)

			upstream := http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
				tick := time.Tick(test.requestDuration)
				select {
				case <-request.Context().Done():
					handlerResultChan <- HandlerResultContextTimeout
				case <-tick:
					handlerResultChan <- HandlerResultTick
					_, err := w.Write([]byte("OK"))
					require.NoError(t, err)
				}
			})

			ts := httptest.NewServer(loghelper.RequestLogMiddleware(zaptest.NewLogger(t), RequestAwareTimeoutMiddleware(test.middlewareTimeout, upstream)))
			defer ts.Close()

			requestURL, err := url.Parse(ts.URL)
			require.NoError(t, err)

			if test.requestTimeout != "" {
				queryParams := requestURL.Query()
				queryParams.Set("timeout", test.requestTimeout)
				requestURL.RawQuery = queryParams.Encode()
			}

			request, err := http.NewRequestWithContext(context.Background(), http.MethodGet, requestURL.String(), nil)
			require.NoError(t, err)

			resp, err := ts.Client().Do(request)
			require.NoError(t, err)

			body, err := io.ReadAll(resp.Body)
			require.NoError(t, err)

			assert.Equal(t, test.expectedResponseBody, string(body))
			assert.Equal(t, test.expectedStatusCode, resp.StatusCode)
			handlerResult := <-handlerResultChan
			assert.Equal(t, test.expectedHandlerResult, handlerResult)
		})
	}
}
