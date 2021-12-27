package http

import (
	"fmt"
	"net/http"
	"time"

	"go.uber.org/zap"

	loghelper "github.com/mrincompetent/eviction-webhook/pkg/log"
)

func RequestAwareTimeoutMiddleware(defaultRequestTimeout time.Duration, next http.Handler) http.Handler {
	return http.HandlerFunc(
		func(w http.ResponseWriter, request *http.Request) {
			log := loghelper.FromContext(request.Context())

			timeout := defaultRequestTimeout
			if v := request.URL.Query().Get("timeout"); v != "" {
				parsedTimeout, err := time.ParseDuration(v)
				if err != nil {
					log.Info(
						"failed to parse 'timeout' from query. Using default",
						zap.Error(err),
						zap.Duration("default-timeout", defaultRequestTimeout),
					)
				} else {
					timeout = parsedTimeout
				}
			}

			log = log.With(zap.Duration("timeout", timeout))
			request = request.WithContext(loghelper.ToContext(request.Context(), log))

			http.TimeoutHandler(
				next,
				timeout,
				fmt.Sprintf("failed to serve the request within the timeout of %s", timeout),
			).ServeHTTP(w, request)
		},
	)
}
