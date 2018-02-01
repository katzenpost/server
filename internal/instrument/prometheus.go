// +build prometheus

package instrument

import (
	"fmt"
	"net/http"

	"github.com/katzenpost/core/wire/commands"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	incoming = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "katzenpost_incoming_total",
			Help: "Number of incoming requests.",
		},
		[]string{"command"},
	)
)

// Init instrumentation
func Init() {
	prometheus.MustRegister(incoming)

	http.Handle("/metrics", promhttp.Handler())
	go http.ListenAndServe(":6543", nil)
}

// Incoming increments the counter for incomming requests
func Incoming(cmd commands.Command) {
	typeStr := fmt.Sprintf("%T", cmd)
	incoming.With(prometheus.Labels{"command": typeStr})
}
