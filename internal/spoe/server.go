package spoe

import (
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
	// Handler receives args extracted from SPOE messages and must return the vars to set.
	// Expected keys in resp:
	//   - Arbitrary SPOE variables (e.g. "policy.use_varnish", "use_varnish", ...)
	Handler func(args map[string]string) (map[string]interface{}, error)
}

func (s *Server) ListenAndServe() error {
	l, err := net.Listen("tcp4", s.Addr)
	if err != nil {
		return err
	}
	defer l.Close()

	spLog := logger.NewDefaultLog()

	h := func(req *request.Request) {
		args := collectArgs(req.Messages)

		resp, err := s.Handler(args)
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

// collectArgs pulls only the keys we care about from the SPOE messages.
// negasus v1.0.7's KV doesn't expose Keys(), so we fetch known keys via Get().
func collectArgs(msgs *message.Messages) map[string]string {
	out := make(map[string]string)

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
		for _, k := range want {
			if _, already := out[k]; already {
				continue
			}
			if v, ok := m.KV.Get(k); ok {
				switch t := v.(type) {
				case string:
					out[k] = t
				case []byte:
					out[k] = string(t)
				case net.IP:
					out[k] = t.String()
				default:
					// ignore unrecognized types; we only expect strings/bytes/IP
				}
			}
		}
	}
	return out
}
