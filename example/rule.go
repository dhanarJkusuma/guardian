package main

import (
	"net/http"
	"strconv"

	"github.com/dhanarJkusuma/guardian/schema"
)

type DashboardRule struct {
	// could be contains database connection or something
}

func (d *DashboardRule) Name() string {
	return "rule_dashboard_owner"
}

func (d *DashboardRule) Execute(user *schema.User, rule *schema.Rule, r *http.Request) bool {
	query := r.URL.Query()
	paramsID := query.Get("user_id")

	userID, err := strconv.ParseInt(paramsID, 10, 64)
	if err != nil {
		return false
	}

	return user.ID == userID
}
