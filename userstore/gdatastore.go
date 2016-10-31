package userstore

import (
	"context"
	"errors"

	"cloud.google.com/go/datastore"
)

const version = 0.1

//type
type Datastore struct {
	db   *datastore.Client
	kind string
}

// errors
var (
	ErrBucketNotFound   = errors.New("Bucket not found")
	ErrBucketCantCreate = errors.New("Could not create bucket")
	ErrKeyNotFound      = errors.New("Key not found")
	ErrDoesNotExist     = errors.New("Does not exist")
	ErrFoundIt          = errors.New("Found it")
	ErrExistsInSet      = errors.New("Element already exists in set")
	ErrInvalidID        = errors.New("Element ID can not contain \":\"")
	ErrCantDelete       = errors.New("Could not delete key")
)

func (d *Datastore) Open(projectId, kind string) error {
	var err error

	d.kind = kind
	d.db, err = datastore.NewClient(context.Background(), projectId)
	if err != nil {
		return err
	}

	return nil
}

func (d *Datastore) Get(key string) (*User, error) {
	user := &User{}

	err := d.db.Get(context.Background(), d.newKey(key), user)
	if err != nil {
		return nil, ErrKeyNotFound
	}

	return user, nil
}

func (d *Datastore) Put(key string, value *User) error {
	_, err := d.db.Put(context.Background(), d.newKey(key), value)
	if err != nil {
		return err
	}

	return nil
}

func (d *Datastore) Del(key string) error {
	err := d.db.Delete(context.Background(), d.newKey(key))
	if err != nil {
		return ErrCantDelete
	}

	return nil
}

func (d *Datastore) Backend() *datastore.Client {
	return d.db
}

func (d *Datastore) Close() {
	d.db.Close()
}

func (d *Datastore) newKey(id string) *datastore.Key {
	return datastore.NewKey(context.Background(), d.kind, id, 0, nil)
}
