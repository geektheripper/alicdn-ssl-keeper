package storage

type StorageService interface {
	Read(key string) ([]byte, error)
	Write(key string, data []byte) error
}
