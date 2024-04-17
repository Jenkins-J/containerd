package integrity

type Validator interface {
	Register(blob string) (string, error)
	IsValid(blob string) (bool, error)
	Unregister(blob string) error
}
