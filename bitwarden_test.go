package bitwarden

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func newTestBitwarden() (*BitwardenServer, *Mockclient) {
	httpClient := &Mockclient{}
	return new(nil, httpClient, "http://localhost"), httpClient
}

func checkRequest(method string, url string, body string) func(req *http.Request) bool {
	return func(req *http.Request) bool {
		data, _ := io.ReadAll(req.Body)
		return req.URL.String() == url &&
			req.Method == method &&
			string(data) == body
	}
}

func TestNewFromURI(t *testing.T) {
	url := "http://test:3429"
	bw := NewFromURL(url)
	assert.Equal(t, bw.url, url)
}

func TestUnlock(t *testing.T) {
	t.Run("Should unlock if password is correct", func(t *testing.T) {
		bw, client := newTestBitwarden()

		client.
			On("Do", mock.MatchedBy(checkRequest(http.MethodPost, "http://localhost/unlock", `{"password":"password"}`))).
			Return(&http.Response{StatusCode: 200}, nil).
			Once()

		err := bw.Unlock(context.Background(), "password")

		client.AssertExpectations(t)
		assert.NoError(t, err)
	})

	t.Run("Should return error if password is not correct", func(t *testing.T) {
		bw, client := newTestBitwarden()

		client.
			On("Do", mock.MatchedBy(checkRequest(http.MethodPost, "http://localhost/unlock", `{"password":"password"}`))).
			Return(&http.Response{StatusCode: 400}, nil).
			Once()

		err := bw.Unlock(context.Background(), "password")

		client.AssertExpectations(t)
		assert.ErrorIs(t, err, ErrWrongPassword)
	})
}

func TestLock(t *testing.T) {
	t.Run("Should lock if no errors", func(t *testing.T) {
		bw, client := newTestBitwarden()

		client.
			On("Do", mock.MatchedBy(checkRequest(http.MethodPost, "http://localhost/lock", `{}`))).
			Return(&http.Response{StatusCode: 200}, nil).
			Once()

		err := bw.Lock(context.Background())

		client.AssertExpectations(t)
		assert.NoError(t, err)
	})

	t.Run("Should return error if error", func(t *testing.T) {
		bw, client := newTestBitwarden()

		client.
			On("Do", mock.MatchedBy(checkRequest(http.MethodPost, "http://localhost/lock", `{}`))).
			Return(&http.Response{StatusCode: 500}, nil).
			Once()

		err := bw.Lock(context.Background())

		client.AssertExpectations(t)
		assert.Error(t, err)
	})
}

func TestRequest(t *testing.T) {
	t.Run("should check for request input data error", func(t *testing.T) {
		bw, _ := newTestBitwarden()

		err := bw.request(context.Background(), http.MethodGet, "/test", make(chan int), nil)
		assert.Error(t, err)
	})

	t.Run("should check if request is valid", func(t *testing.T) {
		bw, _ := newTestBitwarden()
		err := bw.request(context.Background(), "@", "/test", nil, nil)
		assert.Error(t, err)
	})

	t.Run("should check for request error", func(t *testing.T) {
		bw, client := newTestBitwarden()

		testErr := errors.New("test error")
		client.
			On("Do", mock.MatchedBy(checkRequest(http.MethodGet, "http://localhost/test", ``))).
			Return(&http.Response{StatusCode: 200, Body: nil}, testErr).
			Once()

		err := bw.request(context.Background(), http.MethodGet, "/test", nil, nil)
		assert.ErrorIs(t, err, testErr)
	})

	t.Run("should check for not found error", func(t *testing.T) {
		bw, client := newTestBitwarden()

		client.
			On("Do", mock.MatchedBy(checkRequest(http.MethodGet, "http://localhost/test", ``))).
			Return(&http.Response{StatusCode: 404, Body: nil}, nil).
			Once()

		err := bw.request(context.Background(), http.MethodGet, "/test", nil, nil)
		assert.ErrorIs(t, err, ErrNotFound)
	})

	t.Run("should check for other status codes", func(t *testing.T) {
		bw, client := newTestBitwarden()

		client.
			On("Do", mock.MatchedBy(checkRequest(http.MethodGet, "http://localhost/test", ``))).
			Return(&http.Response{StatusCode: 500, Body: nil}, nil).
			Once()

		err := bw.request(context.Background(), http.MethodGet, "/test", nil, nil)
		assert.ErrorIs(t, err, ErrUnexpectedStatusCode)
	})

	t.Run("should check for json decode errors", func(t *testing.T) {
		bw, client := newTestBitwarden()

		respData := []byte(`nonsense:asdf`)

		client.
			On("Do", mock.MatchedBy(checkRequest(http.MethodGet, "http://localhost/test", ``))).
			Return(&http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewBuffer(respData))}, nil).
			Once()

		var resp struct{}
		err := bw.request(context.Background(), http.MethodGet, "/test", nil, resp)
		assert.Error(t, err)
	})
}

func TestGetItem(t *testing.T) {
	t.Run("Should get and parse item if correct", func(t *testing.T) {
		bw, client := newTestBitwarden()

		itemID := "382a9d7b-f6b5-4eaa-92a1-1f3c7d89e48f"
		respData := []byte(`{"data":{"passwordHistory":null,"revisionDate":"2023-05-06T07:08:09.0001Z","creationDate":"2023-01-01T01:02:03.0004Z","deletedDate":null,"object":"item","id":"` + itemID + `","organizationId":null,"folderId":null,"type":2,"reprompt":1,"name":"ENV","notes":"This is a secure note!","favorite":false,"secureNote":{"type":0},"collectionIds":[]}}`)

		client.
			On("Do", mock.MatchedBy(checkRequest(http.MethodGet, "http://localhost/object/item/"+itemID, ``))).
			Return(&http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewBuffer(respData))}, nil).
			Once()

		item, err := bw.GetItem(context.Background(), itemID)

		client.AssertExpectations(t)
		assert.NoError(t, err)
		assert.Equal(t, "2023-01-01T01:02:03.0004Z", item.CreationDate.Format(time.RFC3339Nano))
		assert.NotNil(t, item.Notes)
		assert.Equal(t, "This is a secure note!", *item.Notes)
		assert.Nil(t, item.DeletedDate)
		assert.Equal(t, item.Type, TypeSecureNote)
	})

	t.Run("Should return error when item not found", func(t *testing.T) {
		bw, client := newTestBitwarden()

		itemID := "382a9d7b-f6b5-4eaa-92a1-1f3c7d89e48f"
		respData := []byte(`{"data":null}`)

		client.
			On("Do", mock.MatchedBy(checkRequest(http.MethodGet, "http://localhost/object/item/"+itemID, ``))).
			Return(&http.Response{StatusCode: 404, Body: io.NopCloser(bytes.NewBuffer(respData))}, nil).
			Once()

		item, err := bw.GetItem(context.Background(), itemID)

		client.AssertExpectations(t)
		assert.ErrorIs(t, err, ErrNotFound)
		assert.Nil(t, item)
	})
}

func TestGetLogin(t *testing.T) {
	t.Run("Should check if the type is correct", func(t *testing.T) {
		bw, client := newTestBitwarden()

		itemID := "e1b9a1a8-72e4-4a3c-9a8f-6cd2f58dca17"
		respData := []byte(`{"data":{"passwordHistory":null,"revisionDate":"2023-05-06T07:08:09.0001Z","creationDate":"2023-01-01T01:02:03.0004Z","deletedDate":null,"object":"item","id":"` + itemID + `","organizationId":null,"folderId":null,"type":2,"reprompt":1,"name":"Secret message","notes":"This is a secure note!","favorite":false,"secureNote":{"type":0},"collectionIds":[]}}`)

		client.
			On("Do", mock.MatchedBy(checkRequest(http.MethodGet, "http://localhost/object/item/"+itemID, ``))).
			Return(&http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewBuffer(respData))}, nil).
			Once()

		_, err := bw.GetLogin(context.Background(), itemID)

		client.AssertExpectations(t)
		assert.ErrorIs(t, err, ErrNotALogin)
	})

	t.Run("Should check if login contains data", func(t *testing.T) {
		bw, client := newTestBitwarden()

		itemID := "d17f8bc3-9c74-4a92-af8e-5e1a7a26e609"
		respData := []byte(`{"data":{"passwordHistory":null,"revisionDate":"2021-07-05T16:55:35.966Z","creationDate":"2021-07-05T16:55:35.966Z","deletedDate":null,"object":"item","id":"` + itemID + `","organizationId":null,"folderId":null,"type":1,"reprompt":0,"name":"My secret","notes":null,"favorite":false,"login":null,"collectionIds":[]}}`)

		client.
			On("Do", mock.MatchedBy(checkRequest(http.MethodGet, "http://localhost/object/item/"+itemID, ``))).
			Return(&http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewBuffer(respData))}, nil).
			Once()

		_, err := bw.GetLogin(context.Background(), itemID)

		client.AssertExpectations(t)
		assert.ErrorIs(t, err, ErrEmptyLogin)
	})

	t.Run("Should return usename and password if correct", func(t *testing.T) {
		bw, client := newTestBitwarden()

		itemID := "1d4cf845-8012-4b2d-a924-f9d8c9b7c44a"
		respData := []byte(`{"data":{"passwordHistory":null,"revisionDate":"2021-07-05T16:55:35.966Z","creationDate":"2021-07-05T16:55:35.966Z","deletedDate":null,"object":"item","id":"` + itemID + `","organizationId":null,"folderId":null,"type":1,"reprompt":0,"name":"My secret","notes":null,"favorite":false,"login":{"username":"user1","password":"password1","totp":null,"passwordRevisionDate":null},"collectionIds":[]}}`)

		client.
			On("Do", mock.MatchedBy(checkRequest(http.MethodGet, "http://localhost/object/item/"+itemID, ``))).
			Return(&http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewBuffer(respData))}, nil).
			Once()

		login, err := bw.GetLogin(context.Background(), itemID)

		client.AssertExpectations(t)
		assert.NotNil(t, login.Username)
		assert.Equal(t, "user1", *login.Username)
		assert.NotNil(t, login.Password)
		assert.Equal(t, "password1", *login.Password)
		assert.NoError(t, err)
	})

	t.Run("Should check item errors", func(t *testing.T) {
		bw, client := newTestBitwarden()

		itemID := "1d4cf845-8012-4b2d-a924-f9d8c9b7c44a"
		respData := []byte(`{"data":null}`)

		client.
			On("Do", mock.MatchedBy(checkRequest(http.MethodGet, "http://localhost/object/item/"+itemID, ``))).
			Return(&http.Response{StatusCode: 404, Body: io.NopCloser(bytes.NewBuffer(respData))}, nil).
			Once()

		_, err := bw.GetLogin(context.Background(), itemID)

		client.AssertExpectations(t)
		assert.ErrorIs(t, err, ErrNotFound)
	})
}

func TestGetSecureNote(t *testing.T) {
	t.Run("Should check if the type is correct", func(t *testing.T) {
		bw, client := newTestBitwarden()

		itemID := "1d4cf845-8012-4b2d-a924-f9d8c9b7c44a"
		respData := []byte(`{"data":{"passwordHistory":null,"revisionDate":"2021-07-05T16:55:35.966Z","creationDate":"2021-07-05T16:55:35.966Z","deletedDate":null,"object":"item","id":"` + itemID + `","organizationId":null,"folderId":null,"type":1,"reprompt":0,"name":"My secret","notes":null,"favorite":false,"login":{"username":"user1","password":null,"totp":null,"passwordRevisionDate":null},"collectionIds":[]}}`)

		client.
			On("Do", mock.MatchedBy(checkRequest(http.MethodGet, "http://localhost/object/item/"+itemID, ``))).
			Return(&http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewBuffer(respData))}, nil).
			Once()

		_, err := bw.GetSecureNote(context.Background(), itemID)

		client.AssertExpectations(t)
		assert.ErrorIs(t, err, ErrNotASecureNote)
	})

	t.Run("Should check if secure note contains data", func(t *testing.T) {
		bw, client := newTestBitwarden()

		itemID := "e1b9a1a8-72e4-4a3c-9a8f-6cd2f58dca17"
		respData := []byte(`{"data":{"passwordHistory":null,"revisionDate":"2023-05-06T07:08:09.0001Z","creationDate":"2023-01-01T01:02:03.0004Z","deletedDate":null,"object":"item","id":"` + itemID + `","organizationId":null,"folderId":null,"type":2,"reprompt":1,"name":"Secret message","notes":null,"favorite":false,"secureNote":{"type":0},"collectionIds":[]}}`)

		client.
			On("Do", mock.MatchedBy(checkRequest(http.MethodGet, "http://localhost/object/item/"+itemID, ``))).
			Return(&http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewBuffer(respData))}, nil).
			Once()

		_, err := bw.GetSecureNote(context.Background(), itemID)

		client.AssertExpectations(t)
		assert.ErrorIs(t, err, ErrEmptySecureNote)
	})

	t.Run("Should check item errors", func(t *testing.T) {
		bw, client := newTestBitwarden()

		itemID := "e1b9a1a8-72e4-4a3c-9a8f-6cd2f58dca17"
		respData := []byte(`{"data":null}`)

		client.
			On("Do", mock.MatchedBy(checkRequest(http.MethodGet, "http://localhost/object/item/"+itemID, ``))).
			Return(&http.Response{StatusCode: 404, Body: io.NopCloser(bytes.NewBuffer(respData))}, nil).
			Once()

		_, err := bw.GetSecureNote(context.Background(), itemID)

		client.AssertExpectations(t)
		assert.ErrorIs(t, err, ErrNotFound)
	})

	t.Run("Should return secure note if correct", func(t *testing.T) {
		bw, client := newTestBitwarden()

		itemID := "1d4cf845-8012-4b2d-a924-f9d8c9b7c44a"
		respData := []byte(`{"data":{"passwordHistory":null,"revisionDate":"2021-07-05T16:55:35.966Z","creationDate":"2021-07-05T16:55:35.966Z","deletedDate":null,"object":"item","id":"` + itemID + `","organizationId":null,"folderId":null,"type":2,"reprompt":0,"name":"My secret","notes":"This is very secret!","favorite":false,"login":{"username":"user1","password":"password1","totp":null,"passwordRevisionDate":null},"collectionIds":[]}}`)

		client.
			On("Do", mock.MatchedBy(checkRequest(http.MethodGet, "http://localhost/object/item/"+itemID, ``))).
			Return(&http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewBuffer(respData))}, nil).
			Once()

		note, err := bw.GetSecureNote(context.Background(), itemID)

		client.AssertExpectations(t)
		assert.Nil(t, err)
		assert.Equal(t, "This is very secret!", note)
	})
}
