package api

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"github.com/julienschmidt/httprouter"
	"github.com/pkg/errors"

	"ebpfcontroller/demo/pkg/ebpfmap"
)

type (
	// RedirectRule provides methods to operate ebpf map from the HTTP server
	RedirectRule interface {
		Run() <-chan error
	}

	lbRule struct {
		mapper ebpfmap.RedirectMetaBPFMapper
		router *httprouter.Router
		addr   string
	}
	// ErrorResp is common response object for server
	ErrorResp struct {
		Message string `json:"message"`
	}

	// BackendServer is data structure that a user want specific a backend server for loadbalance
	BackendServer struct {
		Token  string `json:"token"`
		GsAddr string `json:"gsaddress"`
		GsPort string `json:"gsport"`
	}
)

// NewRedirectRule create a RedirectRule object
func NewRedirectRule(mapper ebpfmap.RedirectMetaBPFMapper,
	addr string) RedirectRule {
	return &lbRule{mapper, httprouter.New(), addr}
}

func (l *lbRule) Run() <-chan error {
	l.router.POST("/rules", adapter(l.updateRedirectRules))
	c := make(chan error)
	func() {
		c <- http.ListenAndServe(l.addr, l.router)
	}()
	log.Printf("Server started...")
	return c
}

func adapter(f func(*http.Request, httprouter.Params) (interface{}, error)) httprouter.Handle {
	return func(resp http.ResponseWriter, request *http.Request, params httprouter.Params) {
		result, err := f(request, params)
		resp.Header().Set("content-type", "application/json")
		if err != nil {
			log.Printf("%s processing error: %+v", request.URL.RequestURI(), err)
			resp.WriteHeader(500)
			response, _ := json.Marshal(ErrorResp{err.Error()})
			resp.Write(response)
			return
		}

		response, _ := json.Marshal(result)
		resp.Write(response)
	}
}

func (l *lbRule) updateRedirectRules(request *http.Request, params httprouter.Params) (interface{}, error) {
	decorder := json.NewDecoder(request.Body)
	var servers []BackendServer
	err := decorder.Decode(&servers)
	if err != nil {
		return nil, errors.Wrap(err, "decode request error")
	}

	for _, s := range servers {
		err = l.mapper.Insert(s.GsAddr, s.GsPort, s.Token)
		fmt.Printf("key: %v, value: %v, value: %v\n", s.Token, s.GsAddr, s.GsPort)
		if err != nil {
			return nil, errors.Wrap(err, "set backend server for map error")
		}
	}

	return ErrorResp{"ok"}, nil
}
