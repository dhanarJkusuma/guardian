package main

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/dhanarJkusuma/guardian"
	"github.com/dhanarJkusuma/guardian/auth"
	"github.com/dhanarJkusuma/guardian/schema"
)

type HttpHandler struct {
	guard *guardian.Guardian
}

func (h *HttpHandler) LoginHandler(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()

	// get params
	email := r.FormValue("email")
	password := r.FormValue("password")

	// authenticate user login
	user, token, err := h.guard.Auth.SignIn(auth.LoginParams{
		Identifier: email,
		Password:   password,
	})
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	userJson, _ := json.Marshal(struct {
		Token    string       `json:"token"`
		UserData *schema.User `json:"user_data"`
	}{Token: token, UserData: user})

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(userJson)
}

func (h *HttpHandler) PrivateHandler(w http.ResponseWriter, r *http.Request) {
	secretResource := struct {
		SecretMessage string `json:"secret_message"`
	}{
		SecretMessage: "This is super secret information",
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(secretResource)
}

func (h *HttpHandler) DashboardHandler(w http.ResponseWriter, r *http.Request) {
	user := auth.GetUserLogin(r)
	if user == nil {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	secretResource := struct {
		SecretMessage string `json:"secret_message"`
		Header        string `json:"header"`
	}{
		SecretMessage: "Hello from private dashboard, this page doesn't need RBAC authentication",
		Header:        fmt.Sprintf("Hi %s", user.Username),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(secretResource)
}
