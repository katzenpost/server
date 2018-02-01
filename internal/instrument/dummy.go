// +build !prometheus

package instrument

import (
	"github.com/katzenpost/core/wire/commands"
)

// Init instrumentation
func Init() {}

// Incomming increments the counter for incomming requests
func Incoming(cmd commands.Command) {}
