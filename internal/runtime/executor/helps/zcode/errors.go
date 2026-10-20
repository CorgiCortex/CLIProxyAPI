package zcode

// RequestError leaves credential health unchanged and stops request retries.
type RequestError struct {
	Code    int
	Message string
}

func (e *RequestError) Error() string         { return e.Message }
func (e *RequestError) StatusCode() int       { return e.Code }
func (e *RequestError) IsRequestScoped() bool { return true }
