package tun2socks

import (
	"sync/atomic"

	"github.com/getsentry/sentry-go"
)

type taskPool struct {
	taskChannel       chan func()
	tun2SocksInstance *Tun2Socks
	running           int32
}

func makeTaskPool() *taskPool {
	res := &taskPool{
		taskChannel: make(chan func()),
		running:     0,
	}
	return res
}

func (pool *taskPool) SubmitAsyncTask(task func()) {
	//	if atomic.LoadInt32(&pool.running) == 0 {
	//	go pool.worker()
	//}
	//go func() {
	//	pool.taskChannel <- task
	//}()

	go func() {
		defer sentry.Recover()
		task() //trivial for now
	}()
}

func (pool *taskPool) worker() {
	atomic.StoreInt32(&pool.running, 1)
	for {
		select {
		case task := <-pool.taskChannel:
			task()
		}
	}
}
