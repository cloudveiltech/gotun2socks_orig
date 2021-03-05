package tun2socks

import (
	"log"
	"sync"
	"sync/atomic"
	"time"
)

type taskPool struct {
	taskPool1         []func()
	taskPool2         []func()
	queuePool         *[]func()
	workingPool       *[]func()
	tun2SocksInstance *Tun2Socks

	isPoolRunning int32
	appendMutex   *sync.Mutex
}

func makeTaskPool() *taskPool {
	res := &taskPool{
		taskPool1:     make([]func(), 0),
		taskPool2:     make([]func(), 0),
		isPoolRunning: 0,
		appendMutex:   &sync.Mutex{},
	}

	res.queuePool = &res.taskPool1
	res.workingPool = &res.taskPool2
	return res
}

func (pool *taskPool) SubmitAsyncTask(task func()) {
	pool.appendMutex.Lock()
	*pool.queuePool = append(*pool.queuePool, task)
	pool.appendMutex.Unlock()

	if atomic.LoadInt32(&pool.isPoolRunning) == 0 {
		go pool.worker()
	}
}

func (pool *taskPool) worker() {
	atomic.StoreInt32(&pool.isPoolRunning, 1)

	for {
		if pool.tun2SocksInstance == nil || pool.tun2SocksInstance.stopped {
			atomic.StoreInt32(&pool.isPoolRunning, 0)
			log.Print("Pool worker exit")
			return
		}

		if len(*pool.queuePool) > 0 {
			pool.swapPools()

			for i := 0; i < len(*pool.workingPool); i++ {
				task := (*pool.workingPool)[i]
				task()
			}

			(*pool.workingPool) = make([]func(), 0)
		}
		time.Sleep(time.Millisecond)
	}
}

func (pool *taskPool) swapPools() {
	pool.appendMutex.Lock()
	p := pool.queuePool
	pool.queuePool = pool.workingPool
	pool.workingPool = p
	pool.appendMutex.Unlock()
}
