package kropa

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/devopsfaith/krakend/config"
	"github.com/devopsfaith/krakend/logging"
	"github.com/devopsfaith/krakend/proxy"
)

const authHeader = "Authorization"
const Namespace = "github_com/zean00/kropa"

type xtraConfig struct {
	ServiceAddress string
	PackageName    string
	Directive      string
}

//OpaRequest opa request model
type OpaRequest struct {
	Input Input `json:"input,omitempty" mapstructure:"input"`
}

//OpaResponse opa response model
type OpaResponse struct {
	Result bool `json:"result,omitempty" mapstructure:"result"`
}

//Input opa input model
type Input struct {
	Method string   `json:"method,omitempty" mapstructure:"method"`
	Path   []string `json:"path,omitempty" mapstructure:"path"`
	Token  string   `json:"token,omitempty" mapstructure:"token"`
}

//PermissionError error permission
type PermissionError struct {
}

func (p *PermissionError) Error() string {
	return "Permission denied"
}

//StatusCode error status code
func (p *PermissionError) StatusCode() int {
	return http.StatusUnauthorized
}

// ProxyFactory creates an proxy factory over the injected one adding a JSON Schema
// validator middleware to the pipe when required
func ProxyFactory(l logging.Logger, pf proxy.Factory) proxy.FactoryFunc {
	return proxy.FactoryFunc(func(cfg *config.EndpointConfig) (proxy.Proxy, error) {
		next, err := pf.New(cfg)
		if err != nil {
			return next, err
		}

		conf := configGetter(cfg.ExtraConfig)

		if conf == nil {
			l.Debug("[kropa] No config for jwtextract ")
			return next, nil
		}

		l.Debug("[kropa] package name ", conf.PackageName)
		return newProxy(l, conf, next), nil
	})
}

//BackendFactory create backend factory
func BackendFactory(l logging.Logger, bf proxy.BackendFactory) proxy.BackendFactory {

	return func(cfg *config.Backend) proxy.Proxy {
		conf := configGetter(cfg.ExtraConfig)

		if conf == nil {
			l.Debug("[kropa] No config for jwtextract ")
		} else {
			l.Debug("[kropa] Package name ", conf.PackageName)
		}

		return Middleware(l, conf)(bf(cfg))
	}
}

//Middleware create backend middleware
func Middleware(l logging.Logger, config *xtraConfig) proxy.Middleware {
	return func(next ...proxy.Proxy) proxy.Proxy {
		if len(next) > 1 {
			panic(proxy.ErrTooManyProxies)
		}
		if len(next) < 1 {
			panic(proxy.ErrNotEnoughProxies)
		}
		return func(ctx context.Context, req *proxy.Request) (*proxy.Response, error) {
			res, err := config.checkPermission(l, req)
			if err != nil {
				return nil, err
			}

			if !res {
				return nil, &PermissionError{}
			}

			resp, err := next[0](ctx, req)
			return resp, err
		}
	}
}

func newProxy(l logging.Logger, config *xtraConfig, next proxy.Proxy) proxy.Proxy {
	return func(ctx context.Context, r *proxy.Request) (*proxy.Response, error) {
		res, err := config.checkPermission(l, r)
		if err != nil {
			return nil, err
		}

		if !res {
			return nil, &PermissionError{}
		}

		return next(ctx, r)
	}
}

func configGetter(cfg config.ExtraConfig) *xtraConfig {
	v, ok := cfg[Namespace]
	if !ok {
		return nil
	}
	tmp, ok := v.(map[string]interface{})
	if !ok {
		return nil
	}
	conf := xtraConfig{Directive: "allow"}
	sa, ok := tmp["service_address"].(string)
	if ok {
		conf.ServiceAddress = sa
	} else {
		return nil
	}

	pkg, ok := tmp["package_name"].(string)
	if ok {
		conf.PackageName = pkg
	} else {
		return nil
	}

	dr, ok := tmp["directive"].(string)
	if ok {
		conf.Directive = dr
	}

	return &conf
}

func (x *xtraConfig) checkPermission(l logging.Logger, r *proxy.Request) (bool, error) {
	token := r.Headers[authHeader][0]
	if token == "" {
		l.Debug("[kropa] Token is empty")
	}
	token = strings.TrimPrefix(token, "Bearer ")
	//Just in case using lower case bearer
	token = strings.TrimPrefix(token, "bearer ")

	req := OpaRequest{
		Input: Input{
			Method: r.Method,
			Token:  token,
			Path:   strings.Split(strings.TrimPrefix(r.Path, "/"), "/"),
		},
	}

	o, err := json.Marshal(req)
	if err != nil {
		return false, err
	}
	b := bytes.NewBuffer(o)

	url := x.ServiceAddress + "/v1/data/" + strings.ReplaceAll(x.PackageName, ".", "/") + "/" + x.Directive

	resp, err := http.Post(url, "application/json", b)
	if err != nil {
		l.Error("[kropa] Error calling opa service ", err)
		return false, err
	}

	defer resp.Body.Close()
	rdata, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return false, err
	}

	if resp.StatusCode >= 300 {
		l.Error("[kropa] Non 2XX response ", string(rdata))
		return false, errors.New(string(rdata))
	}

	var result OpaResponse
	if err := json.Unmarshal(rdata, &result); err != nil {
		return false, err
	}

	return result.Result, nil
}
