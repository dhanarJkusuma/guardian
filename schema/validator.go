package schema

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// Validator wrap all validator for guardian schema
type Validator struct {
	User       *UserValidator       `json:"user"`
	Rule       *RuleValidator       `json:"rule"`
	Role       *RoleValidator       `json:"role"`
	Permission *PermissionValidator `json:"permission"`
}

// Initialize function will init nil config for validator
func (v *Validator) Initialize() {
	if v.User == nil {
		v.User = &UserValidator{}
	}
	v.User.FillEmptyValidator()
	if v.Rule == nil {
		v.Rule = &RuleValidator{}
	}
	v.Rule.FillEmptyValidator()
	if v.Role == nil {
		v.Role = &RoleValidator{}
	}
	v.Role.FillEmptyValidator()
	if v.Permission == nil {
		v.Permission = &PermissionValidator{}
	}
	v.Permission.FillEmptyValidator()
}

var (
	defaultMinLengthString = 5
	defaultMaxLengthString = 20

	defaultEmailRegex   = `^(([^<>()\[\]\\.,;:\s@"]+(\.[^<>()\[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$`
	defaultNameRegex    = "^[a-zA-Z0-9_]*$"
	defaultErrNameRegex = "%s only accept lowerCase, upperCase letter, digit, and underscore"
)

// RegexValidator will validate used regex  in some attribute
type RegexValidator struct {
	Regex       string `json:"regex"`
	RegexErrMsg string `json:"regex_err_msg"`
}

// validateRegex will validate regex with specific pattern and err message
func (x *RegexValidator) validateRegex(attr string, s string) error {
	match, _ := regexp.MatchString(x.Regex, s)
	if !match {
		return errors.New(strings.Replace(x.RegexErrMsg, "{attr}", attr, -1))
	}
	return nil
}

// StringValidator will validate string length in some attribute
type StringValidator struct {
	Min *int `json:"min"`
	Max *int `json:"max"`
}

// validateLen will validate string length and return error message
func (n *StringValidator) validateLen(attr string, s string) error {
	sLen := len(s)
	if sLen < *n.Min || sLen > *n.Max {
		return errors.New(fmt.Sprintf("%s must have at least %d and a maximum of %d characters", attr, *n.Min, *n.Max))
	}
	return nil
}

// StringRegexValidator wrap StringValidator and RegexValidator
type StringRegexValidator struct {
	*StringValidator
	Regex *RegexValidator `json:"regex_validation"`
}

// setDefaultStringValidator will set default value for StringValidator
func setDefaultStringValidator() *StringValidator {
	return &StringValidator{
		Min: &defaultMinLengthString,
		Max: &defaultMaxLengthString,
	}
}

// setDefaultRegexValidator will set default value for RegexValidator
func setDefaultRegexValidator() *RegexValidator {
	return &RegexValidator{
		Regex:       defaultNameRegex,
		RegexErrMsg: defaultErrNameRegex,
	}
}

// UserValidator contains constraint for validate user entity
type UserValidator struct {
	Email    *RegexValidator       `json:"email"`
	Username *StringRegexValidator `json:"username"`
	Password *StringRegexValidator `json:"password"`
}

// FillEmptyValidator will fill all nil constraints to prevent NilPointer
func (u *UserValidator) FillEmptyValidator() {
	// username validator
	if u.Username == nil {
		u.Username = &StringRegexValidator{
			StringValidator: setDefaultStringValidator(),
			Regex:           setDefaultRegexValidator(),
		}
	}
	if u.Username.Min == nil {
		u.Username.Min = &defaultMinLengthString
	}
	if u.Username.Max == nil {
		u.Username.Max = &defaultMaxLengthString
	}
	if u.Username.Regex == nil {
		u.Username.Regex = setDefaultRegexValidator()
	}

	// email validator
	if u.Email == nil {
		u.Email = &RegexValidator{
			Regex:       defaultEmailRegex,
			RegexErrMsg: "invalid email format",
		}
	}

	// password validator
	if u.Password.StringValidator == nil {
		u.Password.StringValidator = setDefaultStringValidator()
	}
	if u.Password.Min == nil {
		u.Password.Min = &defaultMinLengthString
	}
	if u.Password.Max == nil {
		u.Password.Max = &defaultMaxLengthString
	}

	if u.Password.Regex == nil {
		u.Password.Regex = setDefaultRegexValidator()
	}
}

// RuleValidator contains constraint for validate rule entity
type RuleValidator struct {
	Name *StringValidator `json:"name"`
}

// FillEmptyValidator will fill all nil constraints to prevent NilPointer
func (r *RuleValidator) FillEmptyValidator() {
	if r.Name == nil {
		r.Name = setDefaultStringValidator()
		return
	}
	if r.Name.Min == nil {
		r.Name.Min = &defaultMinLengthString
	}

	if r.Name.Max == nil {
		r.Name.Max = &defaultMaxLengthString
	}
}

// RoleValidator contains constraint for validate role entity
type RoleValidator struct {
	Name *StringValidator `json:"name"`
}

// FillEmptyValidator will fill all nil constraints to prevent NilPointer
func (r *RoleValidator) FillEmptyValidator() {
	if r.Name == nil {
		r.Name = setDefaultStringValidator()
		return
	}

	if r.Name.Min == nil {
		r.Name.Min = &defaultMinLengthString
	}

	if r.Name.Max == nil {
		r.Name.Max = &defaultMaxLengthString
	}
}

// PermissionValidator contains constraint for validate permission entity
type PermissionValidator struct {
	Name *StringValidator `json:"name"`
}

// FillEmptyValidator will fill all nil constraints to prevent NilPointer
func (p *PermissionValidator) FillEmptyValidator() {
	if p.Name == nil {
		p.Name = setDefaultStringValidator()
		return
	}

	if p.Name.Min == nil {
		p.Name.Min = &defaultMinLengthString
	}

	if p.Name.Max == nil {
		p.Name.Max = &defaultMaxLengthString
	}
}
