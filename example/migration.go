package main

import (
	"net/http"

	"github.com/dhanarJkusuma/guardian/migration"
	"github.com/dhanarJkusuma/guardian/schema"
)

// func for run init admin migration
func InitAdminMigration(g *migration.GuardTx) error {
	var errMig error

	// create migration create user
	adminUser := &schema.User{
		Username: "administrator",
		Email:    "administrator@guardian.com",
		Password: "himitsu",
	}
	errMig = g.Auth.Register(adminUser)
	if errMig != nil {
		return errMig
	}

	secretRoute := &schema.Permission{
		Name:        "rahasia_1",
		Method:      http.MethodGet,
		Route:       "/rahasia",
		Description: "This route contains super secret information",
	}
	errMig = g.Permission(secretRoute).CreatePermission()
	if errMig != nil {
		return errMig
	}

	// create role
	cLevelRole := &schema.Role{
		Name:        "c_level",
		Description: "This role represents the C level in this company",
	}
	errMig = g.Role(cLevelRole).CreateRole()
	if errMig != nil {
		return errMig
	}

	// attach permission in `c_level`
	errMig = cLevelRole.AddPermission(secretRoute)
	if errMig != nil {
		return errMig
	}

	// assign role to the `adminUser`
	errMig = cLevelRole.Assign(adminUser)
	if errMig != nil {
		return errMig
	}

	return nil
}
