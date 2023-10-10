package bitwarden

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os/exec"
	"time"
)

//go:generate go run github.com/vektra/mockery/v2
//go:generate go run golang.org/x/tools/cmd/stringer -type=ItemType,Reprompt

type ItemType int
type Reprompt int
type FieldType int

const (
	port = "4628"

	TypeLogin      ItemType = 1
	TypeSecureNote ItemType = 2
	TypeCard       ItemType = 3
	TypeIdentity   ItemType = 4

	RepromptNo  Reprompt = 0
	RepromptYes Reprompt = 1
)

var (
	ErrNotFound             = errors.New("item not found")
	ErrBadRequest           = errors.New("bad request")
	ErrUnexpectedStatusCode = errors.New("unexpected status code")

	ErrWrongPassword = errors.New("wrong password")

	ErrNotASecureNote  = errors.New("item is not a secure note")
	ErrEmptySecureNote = errors.New("secure note is empty")

	ErrNotALogin  = errors.New("item is not a login")
	ErrEmptyLogin = errors.New("login is empty")
)

type Field struct {
	Name  string    `json:"name"`
	Value string    `json:"value"`
	Type  FieldType `json:"type"` // TODO: don't know what this is
}

type URI struct {
	Match *string
	URI   *string
}

type Login struct {
	URIs     []URI   `json:"uris"`
	Username *string `json:"username"`
	Password *string `json:"password"`
	TOTP     *string `json:"totp"`
}

type Card struct {
	CardHolderName *string `json:"cardHolderName"`
	Brand          *string `json:"brand"`
	Number         *string `json:"number"`
	ExpMonth       *string `json:"expMonth"`
	ExpYear        *string `json:"expYear"`
	Code           *string `json:"code"`
}

type Identity struct {
	Title          *string `json:"title"`
	FirstName      *string `json:"firstName"`
	MiddleName     *string `json:"middleName"`
	LastName       *string `json:"lastName"`
	Address1       *string `json:"address1"`
	Address2       *string `json:"address2"`
	Address3       *string `json:"address3"`
	City           *string `json:"city"`
	State          *string `json:"state"`
	PostalCode     *string `json:"postalCode"`
	Country        *string `json:"country"`
	Company        *string `json:"company"`
	Email          *string `json:"email"`
	Phone          *string `json:"phone"`
	SSN            *string `json:"ssn"`
	Username       *string `json:"username"`
	PassportNumber *string `json:"passportNumber"`
	LicenseNumber  *string `json:"licenseNumber"`
}

type Item struct {
	CreationDate   time.Time  `json:"creationDate"`
	RevisionDate   *time.Time `json:"revisionDate"`
	DeletedDate    *time.Time `json:"deletedDate"`
	OrganizationID *string    `json:"organizationId"`
	CollectionID   *string    `json:"collectionId"`
	FolderID       *string    `json:"folderId"`
	Type           ItemType   `json:"type"`
	Name           *string    `json:"name"`
	Notes          *string    `json:"notes"`
	Favorite       bool       `json:"favorite"`
	Fields         []Field    `json:"fields"`
	Login          *Login     `json:"login"`
	Card           *Card      `json:"card"`
	Identity       *Identity  `json:"identity"`
	Reprompt       Reprompt   `json:"reprompt"`
}

type BitwardenServer struct {
	url    string
	cmd    *exec.Cmd
	client client
}

type client interface {
	Do(req *http.Request) (*http.Response, error)
}

func New() *BitwardenServer {
	cmd := exec.Command("bash", "-c", "bw serve --port "+port) // TODO: this probably does not work for windows
	go func() { cmd.Run() }()
	time.Sleep(100 * time.Millisecond) // not pretty, but wait some time for process to start
	return new(cmd, &http.Client{}, "http://localhost:"+port)
}

func NewFromURL(url string) *BitwardenServer {
	return new(nil, &http.Client{}, url)
}

func new(cmd *exec.Cmd, client client, url string) *BitwardenServer {
	return &BitwardenServer{cmd: cmd, client: client, url: url}
}

func (b *BitwardenServer) Close() {
	if b.cmd != nil {
		b.cmd.Process.Kill() // kill bitwarden server
		b.cmd.Process.Wait() // wait for it to exit (is this needed?)
	}
}

func (b BitwardenServer) request(ctx context.Context, method string, endpoint string, req any, resp any) error {
	url := b.url + endpoint
	var body io.Reader = http.NoBody

	if req != nil {
		var err error
		data, err := json.Marshal(req)
		if err != nil {
			return err
		}
		body = bytes.NewBuffer(data)
	}

	request, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return err
	}

	if req != nil {
		request.Header.Add("Content-Type", "application/json")
	}

	r, err := b.client.Do(request)
	if err != nil {
		return err
	}

	switch r.StatusCode {
	case http.StatusOK:
		break
	case http.StatusNotFound:
		return ErrNotFound
	case http.StatusBadRequest:
		return ErrBadRequest
	default:
		return fmt.Errorf("%w: %d", ErrUnexpectedStatusCode, r.StatusCode)
	}

	if resp != nil {
		if err := json.NewDecoder(r.Body).Decode(resp); err != nil {
			return err
		}
	}
	return nil
}

func (b *BitwardenServer) Unlock(ctx context.Context, password string) error {
	req := struct {
		Password string `json:"password"`
	}{Password: password}

	err := b.request(ctx, http.MethodPost, "/unlock", req, nil)
	if errors.Is(err, ErrBadRequest) { // this is a wrong password as far as I know
		return ErrWrongPassword
	}
	return err
}

func (b *BitwardenServer) Lock(ctx context.Context) error {
	return b.request(ctx, http.MethodPost, "/lock", struct{}{}, nil)
}

func (b *BitwardenServer) GetItem(ctx context.Context, id string) (*Item, error) {
	resp := struct {
		Data Item `json:"data"`
	}{}
	if err := b.request(ctx, http.MethodGet, "/object/item/"+id, nil, &resp); err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func (b *BitwardenServer) GetLogin(ctx context.Context, id string) (*Login, error) {
	i, err := b.GetItem(ctx, id)
	if err != nil {
		return nil, err
	}
	if i.Type != TypeLogin {
		return nil, ErrNotALogin
	}
	if i.Login == nil {
		return nil, ErrEmptyLogin
	}
	return i.Login, nil
}

func (b *BitwardenServer) GetSecureNote(ctx context.Context, id string) (string, error) {
	i, err := b.GetItem(ctx, id)
	if err != nil {
		return "", err
	}
	if i.Type != TypeSecureNote {
		return "", ErrNotASecureNote
	}
	if i.Notes == nil {
		return "", ErrEmptySecureNote
	}
	return *i.Notes, nil
}
