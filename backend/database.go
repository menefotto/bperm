package backend

type Db interface {
	Open(projectId, kind string) error
	Get(key string) (*User, error)
	Put(key string, value *User) error
	Del(key string) error
	Close()
}
