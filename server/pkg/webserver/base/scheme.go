package base

import (
	"net/http"
	"strings"

	"github.com/kataras/iris/v12"
	"github.com/kataras/iris/v12/context"
	"github.com/kataras/iris/v12/core/router"
	"go.uber.org/zap"
)

type Result interface{}

type Handler func(iris.Context) Result
type Hook func(ctx iris.Context) error

type Method struct {
	Register func(path string, handlers ...context.Handler) *router.Route
	Handler  Handler
}

type Route struct {
	Path                   string
	Middlewares            []Hook
	GET, POST, PUT, DELETE Handler
	Desc                   string
	SubRoutes              []Route
}

type Response struct {
	Code    StatusCode  `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data"`
}

func WrapHandler(handler Handler, desc string) iris.Handler {
	return func(ctx iris.Context) {
		result := handler(ctx)
		ctx.Values().Set("routeDesc", desc)
		ctx.StatusCode(iris.StatusOK)
		if result != nil {
			_, _ = ctx.JSON(&result)
		}
	}
}

func SetRoute(r router.Party, route *Route) {
	routePath := route.Path
	hasSubRoutes := len(route.SubRoutes) > 0

	var middleWares []iris.Handler

	if !strings.HasPrefix(routePath, "/") {
		routePath = "/" + routePath
	}

	if len(route.Middlewares) > 0 {
		r.Use(route.Wrap(route.Middlewares)...)
	}

	methods := []Method{
		{r.Get, route.GET},
		{r.Post, route.POST},
		{r.Put, route.PUT},
		{r.Delete, route.DELETE},
	}

	for _, method := range methods {
		if method.Handler != nil {
			zap.L().Info(r.GetRelPath())
			middleWares = append(middleWares, WrapHandler(method.Handler, route.Desc))
			_ = method.Register(routePath, middleWares...)
		}
	}

	if hasSubRoutes {
		pre := r.Party(routePath, middleWares...)
		for _, sub := range route.SubRoutes {
			sub := sub
			SetRoute(pre, &sub)
		}
	}
}

func (rt *Route) Wrap(hooks []Hook) []iris.Handler {
	handlers := make([]iris.Handler, 0)
	for _, hook := range hooks {
		handlers = append(handlers, hookHandler(hook, rt.Desc))
	}
	return handlers
}

func hookHandler(h Hook, desc string) iris.Handler {
	return func(ctx iris.Context) {
		// pass route description to handler
		ctx.Values().Set("routeDesc", desc)

		err := h(ctx)
		if err == nil {
			return
		}

		zap.L().Warn(err.Error())
		resp := &Response{
			Code:    Error,
			Message: err.Error(),
		}

		ctx.StatusCode(http.StatusOK)
		_, err = ctx.JSON(resp)
		if err != nil {
			zap.L().Warn("response error",
				zap.Any("body", resp),
				zap.Error(err))
		}
	}
}
