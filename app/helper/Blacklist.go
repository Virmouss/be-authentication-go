package helper

import (
	"time"
)

type Blacklist struct {
	Tokens map[string]time.Time
}

func NewBlacklist() *Blacklist {
	return &Blacklist{
		Tokens: make(map[string]time.Time),
	}
}

func (b *Blacklist) AddToken(token string, expTime time.Time) {

	b.Tokens[token] = expTime
	//fmt.Println("Blacklist now contains:", b.Tokens)
}

func (b *Blacklist) IsTokenBlacklisted(token string) bool {
	expTime, exists := b.Tokens[token]
	//log.Println(b.Tokens)
	if !exists {
		return false
	}
	return time.Now().Before(expTime)
}
