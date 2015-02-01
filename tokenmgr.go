package jwt

import (
	"sync"
)

type TokenManager struct {
	blocks map[int64]int64 //key:uid
	lock   sync.Mutex
}

func NewTokenManager() (*TokenManager, error) {
	return &TokenManager{
		blocks: make(map[int64]int64),
	}, nil
}

func (m *TokenManager) GC() {
	//TODO:xx
}
func (m *TokenManager) UpdateTokenBlockTime(uid int64, blocktime int64) {
	if blocktime <= 0 {
		return
	}
	m.lock.Lock()
	last_block_time, ok := m.blocks[uid]
	if !ok {
		m.blocks[uid] = blocktime
	} else if blocktime > last_block_time {
		m.blocks[uid] = blocktime
	}

	m.lock.Unlock()
}

func (m *TokenManager) CheckBlockTime(uid int64, blocktime int64) bool {
	if blocktime <= 0 {
		return false
	}
	var f bool = false
	m.lock.Lock()
	last_block_time, ok := m.blocks[uid]
	if !ok {
		m.blocks[uid] = blocktime
		f = true
	} else if blocktime >= last_block_time {
		f = true
	}

	m.lock.Unlock()
	return f
}
