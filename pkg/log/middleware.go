package log

import (
	"bytes"
	"net/http"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

type responseWriter struct {
	next http.ResponseWriter

	responseBody *bytes.Buffer
	statusCode   int
}

func (r *responseWriter) Header() http.Header {
	return r.next.Header()
}

func (r *responseWriter) Write(b []byte) (int, error) {
	r.responseBody.Write(b)

	return r.next.Write(b)
}

func (r *responseWriter) WriteHeader(statusCode int) {
	r.statusCode = statusCode
	r.next.WriteHeader(statusCode)
}

func RequestLogMiddleware(log *zap.Logger, next http.Handler) http.Handler {
	log = log.Named("RequestLogMiddleware")

	return http.HandlerFunc(
		func(w http.ResponseWriter, request *http.Request) {
			log := log.With(
				zap.Object("request", zapcore.ObjectMarshalerFunc(func(encoder zapcore.ObjectEncoder) error {
					encoder.AddString("method", request.Method)
					encoder.AddString("host", request.Host)
					encoder.AddString("remote-address", request.RemoteAddr)
					encoder.AddString("proto", request.Proto)
					encoder.AddString("uri", request.RequestURI)
					encoder.AddString("url", request.URL.String())
					encoder.AddString("user-agent", request.UserAgent())
					encoder.AddString("content-type", request.Header.Get("Content-Type"))
					encoder.AddString("accept", request.Header.Get("Accept"))

					return nil
				})),
			)

			request = request.WithContext(ToContext(request.Context(), log))

			ww := &responseWriter{
				next:         w,
				responseBody: bytes.NewBuffer(nil),
			}
			next.ServeHTTP(ww, request)

			if log.Level() == zapcore.DebugLevel {
				log = log.With(
					zap.Object("response", zapcore.ObjectMarshalerFunc(func(encoder zapcore.ObjectEncoder) error {
						encoder.AddString("body", ww.responseBody.String())
						encoder.AddInt("status-code", ww.statusCode)
						return nil
					})),
				)
			} else {
				log = log.With(
					zap.Object("response", zapcore.ObjectMarshalerFunc(func(encoder zapcore.ObjectEncoder) error {
						encoder.AddInt("status-code", ww.statusCode)
						return nil
					})),
				)
			}

			log.Info("Finished request")
		},
	)
}
