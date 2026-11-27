// Package notify sends alerts to Telegram through the Bot API.
package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

const DefaultTelegramURL = "https://api.telegram.org"

// MaxMessageLen is Telegram's limit for one message's text.
const MaxMessageLen = 4096

var (
	tokenRE  = regexp.MustCompile(`^[0-9]{3,20}:[A-Za-z0-9_-]{30,64}$`)
	chatIDRE = regexp.MustCompile(`^(-?[0-9]{1,20}|@[A-Za-z][A-Za-z0-9_]{4,31})$`)
)

// ValidToken reports whether s looks like a bot token from @BotFather.
func ValidToken(s string) bool { return tokenRE.MatchString(s) }

// ValidChatID accepts a numeric chat ID (negative for groups) or a public
// channel's @username.
func ValidChatID(s string) bool { return chatIDRE.MatchString(s) }

// Telegram is a minimal Bot API client.
type Telegram struct {
	BaseURL string
	HTTP    *http.Client
}

func NewTelegram() *Telegram {
	return &Telegram{BaseURL: DefaultTelegramURL, HTTP: &http.Client{Timeout: 20 * time.Second}}
}

// APIError is an error reply from the Bot API.
type APIError struct {
	Code        int
	Description string
	RetryAfter  time.Duration // set on 429 Too Many Requests
}

func (e *APIError) Error() string {
	return fmt.Sprintf("telegram API error %d: %s", e.Code, e.Description)
}

// Temporary reports whether retrying later might succeed.
func (e *APIError) Temporary() bool { return e.Code == http.StatusTooManyRequests || e.Code >= 500 }

// call posts params to a Bot API method and decodes "result" into out. The
// bot token is part of the URL path, so transport errors are stripped of
// the URL to keep the token out of logs and the UI.
func (t *Telegram) call(ctx context.Context, token, method string, params any, out any) error {
	body, err := json.Marshal(params)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.BaseURL+"/bot"+token+"/"+method, bytes.NewReader(body))
	if err != nil {
		return errors.New("building telegram request failed")
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "dynamic-shodan/1.0")
	resp, err := t.HTTP.Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return fmt.Errorf("telegram request failed: %w", err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return fmt.Errorf("reading telegram response: %w", err)
	}
	var env struct {
		OK          bool            `json:"ok"`
		Result      json.RawMessage `json:"result"`
		ErrorCode   int             `json:"error_code"`
		Description string          `json:"description"`
		Parameters  struct {
			RetryAfter int `json:"retry_after"`
		} `json:"parameters"`
	}
	if err := json.Unmarshal(data, &env); err != nil {
		if resp.StatusCode != http.StatusOK {
			return &APIError{Code: resp.StatusCode, Description: http.StatusText(resp.StatusCode)}
		}
		return fmt.Errorf("decoding telegram response: %w", err)
	}
	if !env.OK {
		code := env.ErrorCode
		if code == 0 {
			code = resp.StatusCode
		}
		desc := env.Description
		if code == http.StatusNotFound || code == http.StatusUnauthorized {
			desc += " (check the bot token)"
		}
		return &APIError{Code: code, Description: desc, RetryAfter: time.Duration(env.Parameters.RetryAfter) * time.Second}
	}
	if out != nil {
		if err := json.Unmarshal(env.Result, out); err != nil {
			return fmt.Errorf("decoding telegram result: %w", err)
		}
	}
	return nil
}

// Send posts an HTML-formatted message to chatID.
func (t *Telegram) Send(ctx context.Context, token, chatID, html string) error {
	return t.call(ctx, token, "sendMessage", map[string]any{
		"chat_id":                  chatID,
		"text":                     Truncate(html, MaxMessageLen),
		"parse_mode":               "HTML",
		"disable_web_page_preview": true,
	}, nil)
}

// BotName returns the bot's @username, which also validates the token.
func (t *Telegram) BotName(ctx context.Context, token string) (string, error) {
	var me struct {
		Username string `json:"username"`
	}
	if err := t.call(ctx, token, "getMe", map[string]any{}, &me); err != nil {
		return "", err
	}
	return me.Username, nil
}

// Chat is a conversation the bot has recently received a message in.
type Chat struct {
	ID    int64
	Title string
	Type  string
}

// RecentChats lists chats from the bot's pending updates, newest first.
// The user finds their chat ID by messaging the bot and calling this.
func (t *Telegram) RecentChats(ctx context.Context, token string) ([]Chat, error) {
	type rawChat struct {
		ID        int64  `json:"id"`
		Type      string `json:"type"`
		Title     string `json:"title"`
		Username  string `json:"username"`
		FirstName string `json:"first_name"`
		LastName  string `json:"last_name"`
	}
	type msg struct {
		Chat rawChat `json:"chat"`
	}
	var updates []struct {
		Message           *msg `json:"message"`
		ChannelPost       *msg `json:"channel_post"`
		MyChatMember      *msg `json:"my_chat_member"`
		EditedMessage     *msg `json:"edited_message"`
		EditedChannelPost *msg `json:"edited_channel_post"`
	}
	if err := t.call(ctx, token, "getUpdates", map[string]any{"limit": 100, "timeout": 0}, &updates); err != nil {
		var apiErr *APIError
		if errors.As(err, &apiErr) && apiErr.Code == http.StatusConflict {
			return nil, errors.New("this bot has a webhook set, so its updates can't be read here; enter the chat ID manually")
		}
		return nil, err
	}
	seen := map[int64]bool{}
	var out []Chat
	for i := len(updates) - 1; i >= 0; i-- {
		u := updates[i]
		for _, m := range []*msg{u.Message, u.ChannelPost, u.MyChatMember, u.EditedMessage, u.EditedChannelPost} {
			if m == nil || m.Chat.ID == 0 || seen[m.Chat.ID] {
				continue
			}
			seen[m.Chat.ID] = true
			c := m.Chat
			title := c.Title
			if title == "" {
				title = strings.TrimSpace(c.FirstName + " " + c.LastName)
			}
			if c.Username != "" {
				title = strings.TrimSpace(title + " (@" + c.Username + ")")
			}
			out = append(out, Chat{ID: c.ID, Title: title, Type: c.Type})
		}
	}
	return out, nil
}

// Truncate shortens an HTML message to at most max bytes, cutting at a line
// break so tags opened on earlier lines stay balanced.
func Truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	const tail = "\n…"
	cut := strings.LastIndex(s[:max-len(tail)], "\n")
	if cut <= 0 {
		cut = max - len(tail)
		for cut > 0 && s[cut]&0xC0 == 0x80 {
			cut--
		}
	}
	return s[:cut] + tail
}
