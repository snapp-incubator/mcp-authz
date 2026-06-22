package mattermost

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/websocket"
)

// Post is the subset of a Mattermost post the bot acts on.
type Post struct {
	ID        string `json:"id"`
	UserID    string `json:"user_id"`
	ChannelID string `json:"channel_id"`
	Message   string `json:"message"`
}

// PostHandler is invoked for every incoming post that is not from the bot.
// Returning an error is logged but does not stop the listener.
type PostHandler func(ctx context.Context, p Post) error

// Listen connects to the Mattermost WebSocket and dispatches "posted" events to
// h until ctx is cancelled. It reconnects with backoff on any connection error.
func (c *Client) Listen(ctx context.Context, botUserID string, h PostHandler, log *slog.Logger) {
	backoff := time.Second
	for ctx.Err() == nil {
		if err := c.listenOnce(ctx, botUserID, h, log); err != nil && ctx.Err() == nil {
			log.Warn("websocket disconnected, reconnecting", "err", err, "backoff", backoff)
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}
			if backoff < 30*time.Second {
				backoff *= 2
			}
			continue
		}
		backoff = time.Second
	}
}

func (c *Client) listenOnce(ctx context.Context, botUserID string, h PostHandler, log *slog.Logger) error {
	wsURL := strings.Replace(c.baseURL, "http", "ws", 1) + "/api/v4/websocket"
	hdr := http.Header{"Authorization": []string{"Bearer " + c.token}}

	conn, _, err := websocket.DefaultDialer.DialContext(ctx, wsURL, hdr)
	if err != nil {
		return fmt.Errorf("dial %s: %w", wsURL, err)
	}
	defer func() { _ = conn.Close() }()
	log.Info("websocket connected", "url", wsURL)

	// Close the connection when ctx is cancelled so the read loop unblocks.
	go func() {
		<-ctx.Done()
		_ = conn.Close()
	}()

	for {
		var ev struct {
			Event string `json:"event"`
			Data  struct {
				Post string `json:"post"` // JSON-encoded Post
			} `json:"data"`
		}
		if err := conn.ReadJSON(&ev); err != nil {
			return err
		}
		if ev.Event != "posted" || ev.Data.Post == "" {
			continue
		}
		var p Post
		if err := json.Unmarshal([]byte(ev.Data.Post), &p); err != nil {
			log.Warn("decode post", "err", err)
			continue
		}
		if p.UserID == botUserID {
			continue // ignore the bot's own messages
		}
		if err := h(ctx, p); err != nil {
			log.Error("handle post", "post", p.ID, "user", p.UserID, "err", err)
		}
	}
}
