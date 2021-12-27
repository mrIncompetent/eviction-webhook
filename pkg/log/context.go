package log

import (
	"context"

	"go.uber.org/zap"
)

type ContextKey string

func (c ContextKey) String() string {
	return "context key " + string(c)
}

var (
	contextKeyLog = ContextKey("log")
)

func ToContext(ctx context.Context, log *zap.Logger) context.Context {
	return context.WithValue(ctx, contextKeyLog, log)
}

func FromContext(ctx context.Context) *zap.Logger {
	log := ctx.Value(contextKeyLog)
	if log == nil {
		return zap.NewNop()
	}

	return log.(*zap.Logger)
}
