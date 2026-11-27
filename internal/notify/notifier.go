package notify

import (
	"context"
	"errors"
	"log"
	"sync"
	"time"

	"dynamic-shodan/internal/model"
)

// Event is a kind of notification the user can switch on or off.
type Event int

const (
	EventIPChange Event = iota // public IP changed
	EventExposure              // new current services or vulnerabilities
	EventHealth                // checks started failing or recovered
)

func (e Event) enabled(c model.Config) bool {
	switch e {
	case EventIPChange:
		return c.NotifyIPChange
	case EventExposure:
		return c.NotifyExposure
	case EventHealth:
		return c.NotifyHealth
	}
	return false
}

// Status is the outcome of the most recent delivery attempt.
type Status struct {
	LastSent  time.Time
	LastError string
	ErrorAt   time.Time
}

// Notifier queues messages and delivers them in the background, so a slow
// or rate-limited Telegram never holds up a check.
type Notifier struct {
	TG     *Telegram
	config func() model.Config
	queue  chan string

	mu     sync.Mutex
	status Status
}

func New(config func() model.Config) *Notifier {
	return &Notifier{TG: NewTelegram(), config: config, queue: make(chan string, 64)}
}

// Notify queues msg (Telegram HTML) if Telegram is set up and the event is
// enabled. It never blocks; if the queue is full the message is dropped.
// A nil Notifier does nothing.
func (n *Notifier) Notify(ev Event, msg string) {
	if n == nil {
		return
	}
	cfg := n.config()
	if !cfg.TelegramEnabled() || !ev.enabled(cfg) {
		return
	}
	select {
	case n.queue <- msg:
	default:
		log.Print("telegram: queue full, dropping notification")
	}
}

func (n *Notifier) Status() Status {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.status
}

// Run delivers queued messages until ctx ends.
func (n *Notifier) Run(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case msg := <-n.queue:
			n.deliver(ctx, msg)
		}
	}
}

func (n *Notifier) deliver(ctx context.Context, msg string) {
	var err error
	for attempt := 0; attempt < 4; attempt++ {
		cfg := n.config() // re-read: settings may change while queued
		if !cfg.TelegramEnabled() {
			return
		}
		sctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		err = n.TG.Send(sctx, cfg.TelegramBotToken, cfg.TelegramChatID, msg)
		cancel()
		if err == nil {
			n.mu.Lock()
			n.status.LastSent = time.Now()
			n.status.LastError = ""
			n.mu.Unlock()
			return
		}
		wait := time.Duration(1<<attempt) * 5 * time.Second
		var apiErr *APIError
		if errors.As(err, &apiErr) {
			if !apiErr.Temporary() {
				break
			}
			if apiErr.RetryAfter > 0 {
				wait = apiErr.RetryAfter
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
	}
	log.Printf("telegram: %v", err)
	n.mu.Lock()
	n.status.LastError = err.Error()
	n.status.ErrorAt = time.Now()
	n.mu.Unlock()
}
