package openaicompat

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/maxqstudio/max-remote-commander/internal/chat"
)

const maxResponseBytes int64 = 8 << 20

var (
	ErrInvalidConfig   = errors.New("invalid OpenAI-compatible provider configuration")
	ErrProviderResponse = errors.New("invalid OpenAI-compatible provider response")
)

type Config struct {
	BaseURL string
	APIKey  string
	Model   string
	Client  *http.Client
}

type Provider struct {
	base   *url.URL
	apiKey string
	model  string
	client *http.Client
}

func New(cfg Config) (*Provider, error) {
	if cfg.Model == "" {
		return nil, ErrInvalidConfig
	}
	u, err := url.Parse(cfg.BaseURL)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, ErrInvalidConfig
	}
	if u.Scheme != "https" {
		if u.Scheme != "http" || !loopbackHost(u.Hostname()) {
			return nil, ErrInvalidConfig
		}
	}
	u.Path = strings.TrimRight(u.Path, "/")
	client := cfg.Client
	if client == nil {
		client = &http.Client{
			Timeout: 60 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return errors.New("redirect refused")
			},
		}
	}
	return &Provider{base:u, apiKey:cfg.APIKey, model:cfg.Model, client:client}, nil
}

func loopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

type apiFunction struct {
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	Parameters  json.RawMessage `json:"parameters,omitempty"`
	Arguments   string          `json:"arguments,omitempty"`
}

type apiToolCall struct {
	ID       string      `json:"id"`
	Type     string      `json:"type"`
	Function apiFunction `json:"function"`
}

type apiMessage struct {
	Role       string        `json:"role"`
	Content    *string       `json:"content,omitempty"`
	ToolCalls  []apiToolCall `json:"tool_calls,omitempty"`
	ToolCallID string        `json:"tool_call_id,omitempty"`
}

type apiTool struct {
	Type     string      `json:"type"`
	Function apiFunction `json:"function"`
}

type apiRequest struct {
	Model      string       `json:"model"`
	Messages   []apiMessage `json:"messages"`
	Tools      []apiTool    `json:"tools,omitempty"`
	ToolChoice string       `json:"tool_choice,omitempty"`
}

type apiResponse struct {
	Choices []struct {
		Message apiMessage `json:"message"`
	} `json:"choices"`
	Error *struct {
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

func toAPIMessages(messages []chat.Message) ([]apiMessage, error) {
	result := make([]apiMessage, 0, len(messages))
	for _, message := range messages {
		item := apiMessage{Role:string(message.Role)}
		switch message.Role {
		case chat.RoleSystem, chat.RoleUser:
			content := message.Content
			item.Content = &content
		case chat.RoleAssistant:
			if message.Content != "" {
				content := message.Content
				item.Content = &content
			}
			for _, call := range message.ToolCalls {
				if call.ID == "" || call.Name == "" || len(call.Arguments) == 0 || !json.Valid(call.Arguments) {
					return nil, chat.ErrInvalidToolCall
				}
				item.ToolCalls = append(item.ToolCalls, apiToolCall{
					ID:call.ID,
					Type:"function",
					Function:apiFunction{Name:call.Name, Arguments:string(call.Arguments)},
				})
			}
		case chat.RoleTool:
			if message.ToolCallID == "" {
				return nil, chat.ErrInvalidToolCall
			}
			content := message.Content
			item.Content = &content
			item.ToolCallID = message.ToolCallID
		default:
			return nil, fmt.Errorf("%w: unknown role %q", ErrInvalidConfig, message.Role)
		}
		result = append(result, item)
	}
	return result, nil
}

func toAPITools(tools []chat.ToolDefinition) ([]apiTool, error) {
	result := make([]apiTool, 0, len(tools))
	for _, tool := range tools {
		if tool.Name == "" || len(tool.Parameters) == 0 || !json.Valid(tool.Parameters) {
			return nil, chat.ErrInvalidToolCall
		}
		result = append(result, apiTool{
			Type:"function",
			Function:apiFunction{
				Name:tool.Name,
				Description:tool.Description,
				Parameters:append(json.RawMessage(nil), tool.Parameters...),
			},
		})
	}
	return result, nil
}

func (p *Provider) Complete(ctx context.Context, request chat.CompletionRequest) (chat.Completion, error) {
	messages, err := toAPIMessages(request.Messages)
	if err != nil {
		return chat.Completion{}, err
	}
	tools, err := toAPITools(request.Tools)
	if err != nil {
		return chat.Completion{}, err
	}
	body := apiRequest{Model:p.model, Messages:messages, Tools:tools}
	if len(tools) > 0 {
		body.ToolChoice = "auto"
	}
	data, err := json.Marshal(body)
	if err != nil {
		return chat.Completion{}, err
	}

	endpoint := *p.base
	endpoint.Path = strings.TrimRight(p.base.Path, "/") + "/chat/completions"
	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), bytes.NewReader(data))
	if err != nil {
		return chat.Completion{}, err
	}
	httpRequest.Header.Set("Content-Type", "application/json")
	if p.apiKey != "" {
		httpRequest.Header.Set("Authorization", "Bearer "+p.apiKey)
	}
	response, err := p.client.Do(httpRequest)
	if err != nil {
		return chat.Completion{}, err
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes+1))
	if err != nil {
		return chat.Completion{}, err
	}
	if int64(len(raw)) > maxResponseBytes {
		return chat.Completion{}, fmt.Errorf("%w: response too large", ErrProviderResponse)
	}
	var decoded apiResponse
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return chat.Completion{}, fmt.Errorf("%w: invalid JSON", ErrProviderResponse)
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		message := ""
		if decoded.Error != nil {
			message = decoded.Error.Message
		}
		return chat.Completion{}, fmt.Errorf("%w: HTTP %d: %s", ErrProviderResponse, response.StatusCode, message)
	}
	if len(decoded.Choices) == 0 {
		return chat.Completion{}, fmt.Errorf("%w: missing choice", ErrProviderResponse)
	}

	message := decoded.Choices[0].Message
	completion := chat.Completion{}
	if message.Content != nil {
		completion.Content = *message.Content
	}
	for _, call := range message.ToolCalls {
		if call.Type != "function" || call.ID == "" || call.Function.Name == "" || !json.Valid([]byte(call.Function.Arguments)) {
			return chat.Completion{}, fmt.Errorf("%w: malformed tool call", ErrProviderResponse)
		}
		completion.ToolCalls = append(completion.ToolCalls, chat.ToolCall{
			ID:call.ID,
			Name:call.Function.Name,
			Arguments:json.RawMessage(call.Function.Arguments),
		})
	}
	return completion, nil
}
