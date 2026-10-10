package faultinject

import (
	"errors"
	"fmt"
)

// ErrInjected marks every error and panic value produced by an armed point.
var ErrInjected = errors.New("faultinject: injected fault")

// ErrCloseConn is wrapped by the error of a point armed with CloseConn: the
// call site closes the connection it is using and fails as if the peer had
// closed it. It matches ErrInjected as well.
var ErrCloseConn = fmt.Errorf("faultinject: close conn: %w", ErrInjected)
