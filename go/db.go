package gotun2socks

import (
	"fmt"
	"log"

	bolt "go.etcd.io/bbolt"
)

var boltDb *BoltDB

type BoltDB struct {
	db          *bolt.DB
	transaction *bolt.Tx
}

func NewBoltDB(filepath string) *BoltDB {
	db, err := bolt.Open(filepath+"/filter.db", 0600, nil)
	if err != nil {
		log.Fatal(err)
	}

	db.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists([]byte("BlockedDomains"))
		if err != nil {
			return fmt.Errorf("create bucket: %s", err)
		}
		return nil
	})

	boltDb = &BoltDB{db, nil}
	return boltDb
}

func (b *BoltDB) Path() string {
	return b.db.Path()
}

func (b *BoltDB) Close() {
	b.db.Close()
}

func (b *BoltDB) AddBlockedDomain(domain string, filterType byte) bool {
	bucket := b.transaction.Bucket([]byte("BlockedDomains"))

	value := make([]byte, 1)
	value[0] = filterType
	err := bucket.Put([]byte(domain), value)
	if err != nil {
		log.Printf("Error adding to domains %s", err)
		return false
	}

	return true
}

func (b *BoltDB) BeginTransaction() bool {
	var err error
	b.transaction, err = b.db.Begin(true)
	if err != nil {
		log.Printf("Error begin transaction %s", err)
		b.transaction = nil
		return false
	}
	return true
}

func (b *BoltDB) CommitTransaction() {
	if b.transaction != nil {
		b.transaction.Commit()
		b.transaction = nil
	}
}

func (b *BoltDB) IsDomainBlocked(domain string) bool {
	tx, err := b.db.Begin(false)
	if err != nil {
		log.Printf("Error begin transaction %s", err)
		return false
	}
	bucket := tx.Bucket([]byte("BlockedDomains"))
	res := bucket.Get([]byte(domain)) != nil
	log.Printf("Checking domain %s is blocked? %t", domain, res)
	tx.Rollback()
	return res
}
