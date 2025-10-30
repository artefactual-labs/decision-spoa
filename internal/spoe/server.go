package spoe

import (
	"fmt"
	"log"
	"net"

	"github.com/negasus/haproxy-spoe-go/action"
	"github.com/negasus/haproxy-spoe-go/agent"
	"github.com/negasus/haproxy-spoe-go/logger"
	"github.com/negasus/haproxy-spoe-go/message"
	"github.com/negasus/haproxy-spoe-go/request"
)

// Server is a thin wrapper around the negasus SPOE agent.
type Server struct {
	Addr   string
	Logger *log.Logger
	// Handler receives args extracted from SPOE messages, along with the raw key/value inputs (as strings),
	// and must return the vars to set.
	// Expected keys in resp:
	//   - Arbitrary SPOE variables (e.g. "policy.use_varnish", "use_varnish", ...)
	Handler func(args map[string]string, raw map[string]string) (map[string]interface{}, error)
}

func (s *Server) ListenAndServe() error {
	l, err := net.Listen("tcp4", s.Addr)
	if err != nil {
		return err
	}
	defer l.Close()

	spLog := logger.NewDefaultLog()

	h := func(req *request.Request) {
		args, raw := collectArgs(req.Messages)

		resp, err := s.Handler(args, raw)
		if err != nil {
			// best-effort: do not set any vars on error
			return
		}

		scope := action.ScopeTransaction
		for k, v := range resp {
			if k == "" {
				continue
			}
			req.Actions.SetVar(scope, k, v)
		}
	}

	a := agent.New(h, spLog)

	if s.Logger != nil {
		s.Logger.Printf("spoe: listening on %s", s.Addr)
	}
	return a.Serve(l)
}

// collectArgs returns both the subset of keys used by the policy engine and a raw view of all inputs.
func collectArgs(msgs *message.Messages) (map[string]string, map[string]string) {
	out := make(map[string]string)
	raw := make(map[string]string)

	want := []string{
		"src",
		"xff",
		"ua",
		"host",
		"path",
		"method",
		"query",
		"ssl_sni",
		"ja3",
		"backend",
		"frontend",
		"protocol",
	}

	for i := 0; i < msgs.Len(); i++ {
		m, err := msgs.GetByIndex(i)
		if err != nil || m == nil || m.KV == nil {
			continue
		}
		items := m.KV.Data()
		for _, item := range items {
			if _, already := raw[item.Name]; already {
				continue
			}
			raw[item.Name] = stringify(item.Value)
		}
		for _, k := range want {
			if _, already := out[k]; already {
				continue
			}
			if v, ok := raw[k]; ok {
				out[k] = v
			}
		}
	}
	return out, raw
}

func stringify(v interface{}) string {
	switch t := v.(type) {
	case string:
		return t
	case []byte:
		return string(t)
	case net.IP:
		return t.String()
	default:
		return fmt.Sprint(v)
	}
}
