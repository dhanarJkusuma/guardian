package auth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-redis/redis"

	"github.com/dhanarJkusuma/guardian/schema"
	"github.com/dhanarJkusuma/guardian/auth/password"
	"github.com/dhanarJkusuma/guardian/auth/token"
)

var (
	ErrInvalidPasswordLogin = errors.New("invalid password")
	ErrInvalidUserLogin     = errors.New("invalid user")
	ErrCreatingToken        = errors.New("error while create a new auth token")
	ErrCreatingCookie       = errors.New("error while set cookie")
	ErrInvalidCookie        = errors.New("invalid cookie")
	ErrInvalidAuthorization = errors.New("invalid authorization")
	ErrValidateCookie       = errors.New("error validate cookie")
	ErrUserNotFound         = errors.New("user not found")
	ErrUserNotActive        = errors.New("user is not active")
)

type LoginParams struct {
	Identifier string
	Password   string
}

type LoginMethod int

const (
	LoginEmail         LoginMethod = 0
	LoginUsername      LoginMethod = 1
	LoginEmailUsername LoginMethod = 2

	CookieBasedAuth int = 0
	TokenBasedAuth  int = 1

	authorization string = "Authorization"
	UserPrinciple string = "UserPrinciple"
)

type Options struct {
	SessionName  string
	GuardSchema  *schema.Schema
	CacheClient  *redis.Client
	LoginMethod  LoginMethod
	ExpiredInSec int64

	TokenStrategy    token.TokenGenerator
	PasswordStrategy password.PasswordGenerator
}

// Auth is an entity that has responsibility to handle authentication in the guardian library
type Auth struct {
	sessionName      string
	cacheClient      *redis.Client
	loginMethod      LoginMethod
	expiredInSeconds int64

	tokenStrategy    token.TokenGenerator
	passwordStrategy password.PasswordGenerator

	dbSchema *schema.Schema
	rules    map[string]schema.RuleExecutor
}

// NewAuth acts as constructor with the required params
func NewAuth(opts Options) *Auth {
	authModule := &Auth{
		sessionName:      opts.SessionName,
		dbSchema:         opts.GuardSchema,
		cacheClient:      opts.CacheClient,
		loginMethod:      opts.LoginMethod,
		expiredInSeconds: opts.ExpiredInSec,
		tokenStrategy:    opts.TokenStrategy,
		passwordStrategy: opts.PasswordStrategy,
		rules:            make(map[string]schema.RuleExecutor),
	}

	return authModule
}

// RegisterRule will register rule executor in the auth module
func (a *Auth) RegisterRule(executor schema.RuleExecutor) {
	if executor != nil {
		a.rules[executor.Name()] = executor
	}
}

// Authenticate function will authenticate user by LoginParams and return user entity if user has successfully login
// Authenticate function will get the data from database
// if user exist, password request validated, and logged user has active status, then loggedUser entity will be returned, otherwise it'll return error
func (a *Auth) Authenticate(params LoginParams) (*schema.User, error) {
	var loggedUser *schema.User
	var err error

	switch a.loginMethod {
	case LoginEmail:
		loggedUser, err = a.dbSchema.User(nil).
			FindUser(map[string]interface{}{
				"email": params.Identifier,
			})
	case LoginUsername:
		loggedUser, err = a.dbSchema.User(nil).
			FindUser(map[string]interface{}{
				"username": params.Identifier,
			})
	case LoginEmailUsername:
		loggedUser, err = a.dbSchema.User(nil).
			FindUserByUsernameOrEmail(params.Identifier)
	}
	if loggedUser == nil {
		return nil, ErrInvalidUserLogin
	}
	if err != nil {
		return nil, err
	}

	if !a.passwordStrategy.ValidatePassword(loggedUser.Password, params.Password) {
		return nil, ErrInvalidPasswordLogin
	}

	if !loggedUser.Active {
		return nil, ErrUserNotActive
	}
	return loggedUser, nil
}

// SignInCookie will authenticate user login and set the cookie with validated user session
// It'll generate a cookie token with specific tokenStrategy and set the token in the redis with the specific key and expiredTime
func (a *Auth) SignInCookie(w http.ResponseWriter, params LoginParams) (*schema.User, error) {
	loggedUser, err := a.Authenticate(params)
	if err != nil {
		return nil, err
	}

	hashCookie := a.tokenStrategy.GenerateCookie()
	http.SetCookie(w, &http.Cookie{
		Name:    a.sessionName,
		Value:   hashCookie,
		Path:    "/",
		Expires: time.Now().Add(time.Duration(a.expiredInSeconds)),
	})

	err = a.cacheClient.Do(
		"SETEX",
		hashCookie,
		strconv.FormatInt(a.expiredInSeconds, 10),
		loggedUser.ID,
	).Err()
	if err != nil {
		return nil, ErrCreatingCookie
	}

	return loggedUser, nil
}

// ClearSession function will clear the login session with the provided cookie
// It'll delete cookie in the redis db and set the empty cookie as response to user
func (a *Auth) ClearSession(w http.ResponseWriter, r *http.Request) error {
	cookieData, err := r.Cookie(a.sessionName)
	if err != nil {
		return ErrInvalidCookie
	}
	cookie := cookieData.Value
	err = a.cacheClient.Do(
		"DEL",
		cookie,
	).Err()
	if err != nil {
		return err
	}

	// clear cookie
	http.SetCookie(w, &http.Cookie{
		Name:   a.sessionName,
		Value:  "",
		Path:   "/",
		MaxAge: -1,
	})
	return nil
}

// SignInCookie will authenticate user login and return token string for authentication based token
// It'll generate a token with specific tokenStrategy and set the token in the redis with the specific key and expiredTime
func (a *Auth) SignIn(params LoginParams) (*schema.User, string, error) {
	loggedUser, err := a.Authenticate(params)
	if err != nil {
		return nil, "", err
	}

	token := a.tokenStrategy.GenerateToken()
	err = a.cacheClient.Do(
		"SETEX",
		token,
		strconv.FormatInt(a.expiredInSeconds, 10),
		loggedUser.ID,
	).Err()
	if err != nil {
		return nil, "", ErrCreatingToken
	}

	return loggedUser, token, nil
}

// Logout function will clear the login session with the provided header Authorization
// It'll delete token data in the redis db
func (a *Auth) Logout(request *http.Request) error {
	var err error
	var user *schema.User

	user = GetUserLogin(request)
	if user == nil {
		return ErrInvalidUserLogin
	}

	token := request.Header.Get(authorization)
	err = a.cacheClient.Do(
		"DEL",
		token,
	).Err()
	if err != nil {
		return err
	}
	return nil
}

// Register function will create a new user with hashed password that provided by auth module
// This function will return error that indicate user creation is success or not
func (a *Auth) Register(user *schema.User) error {
	userSchema := a.dbSchema.User(user)
	userSchema.Password = a.passwordStrategy.HashPassword(user.Password)
	return userSchema.CreateUser()
}

/* HTTP Protection */
func (a *Auth) authenticateRoute(w http.ResponseWriter, r *http.Request, strategy int) error {
	user, err := a.getUserPrinciple(r, strategy)
	if err != nil {
		switch strategy {
		case CookieBasedAuth:
			a.ClearSession(w, r)
		}
		w.WriteHeader(http.StatusUnauthorized)
		return err
	}
	ctx := context.WithValue(r.Context(), UserPrinciple, user)
	r = r.WithContext(ctx)
	return nil
}

// AuthenticateCookieHandler is a middleware func that protect the specific route handler using cookie based authentication
func (a *Auth) AuthenticateCookieHandler(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		err := a.authenticateRoute(w, r, CookieBasedAuth)
		if err != nil {
			return
		}
		handler.ServeHTTP(w, r)
	})
}

// AuthenticateCookieHandlerFunc is a middleware func that protect the specific route handler as handlerFunc using cookie based authentication
func (a *Auth) AuthenticateCookieHandlerFunc(handler func(w http.ResponseWriter, r *http.Request)) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		err := a.authenticateRoute(w, r, CookieBasedAuth)
		if err != nil {
			return
		}
		handler(w, r)
	}
}

// AuthenticateHandler is a middleware func that protect the specific route handler using token based authentication
func (a *Auth) AuthenticateHandler(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		err := a.authenticateRoute(w, r, TokenBasedAuth)
		if err != nil {
			return
		}
		handler.ServeHTTP(w, r)
	})
}

// AuthenticateHandlerFunc is a middleware func that protect the specific route handler as handlerFunc using token based authentication
func (a *Auth) AuthenticateHandlerFunc(handler func(w http.ResponseWriter, r *http.Request)) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		err := a.authenticateRoute(w, r, TokenBasedAuth)
		if err != nil {
			return
		}
		handler(w, r)
	}
}

// authenticateRBAC will authenticate user role and permission.
// this function will execute all rules that associated with this specific role, and permission
func (a *Auth) authenticateRBAC(w http.ResponseWriter, r *http.Request) error {
	user := GetUserLogin(r)
	if user == nil {
		w.WriteHeader(http.StatusUnauthorized)
		return errors.New("user not found")
	}

	isAllowed, err := a.dbSchema.User(user).CanAccess(r.Method, r.URL.Path)
	if err != nil || !isAllowed {
		w.WriteHeader(http.StatusForbidden)
		return err
	}

	// check rule for specific resource
	ctx := r.Context()
	roles, err := a.dbSchema.Role(nil).GetRolesResourceContext(
		ctx,
		user,
		r.Method,
		r.URL.Path,
	)
	if err != nil {
		w.WriteHeader(http.StatusForbidden)
		return err
	}

	permission, err := a.dbSchema.Permission(nil).GetPermissionByResource(r.Method, r.URL.Path)
	if err != nil {
		w.WriteHeader(http.StatusForbidden)
		return err
	}

	var rules []schema.Rule

	// check rules by Role schema
	rules, err = a.dbSchema.Rule(nil).GetRolesRule(roles)
	if err != nil {
		w.WriteHeader(http.StatusForbidden)
		return err
	}

	err = a.executeRules(user, rules)
	if err != nil {
		w.WriteHeader(http.StatusForbidden)
		return err
	}

	// check rules by Permission schema
	rules, err = a.dbSchema.Rule(nil).GetPermissionRuleContext(ctx, *permission)
	err = a.executeRules(user, rules)
	if err != nil {
		w.WriteHeader(http.StatusForbidden)
		return err
	}

	return nil
}

// executeRules will execute all rule in rules collection
func (a *Auth) executeRules(user *schema.User, rules []schema.Rule) error {
	for _, rule := range rules {
		if ruleExecutor, ok := a.rules[rule.Name]; ok {
			isRuleAllowed := ruleExecutor.Execute(user)
			if !isRuleAllowed {
				return errors.New(fmt.Sprintf("blocked by rule %s", ruleExecutor.Name()))
			}
		}
	}
	return nil
}

// AuthenticateRBACCookieHandler is a middleware func that protect the specific route handler using cookie based authentication and RBAC
func (a *Auth) AuthenticateRBACCookieHandler(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var err error
		err = a.authenticateRoute(w, r, CookieBasedAuth)
		if err != nil {
			return
		}

		err = a.authenticateRBAC(w, r)
		if err != nil {
			return
		}

		handler.ServeHTTP(w, r)
	})
}

// AuthenticateRBACCookieHandlerFunc is a middleware func that protect the specific route handler as HandlerFunc using cookie based authentication and RBAC
func (a *Auth) AuthenticateRBACCookieHandlerFunc(handler func(w http.ResponseWriter, r *http.Request)) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		var err error
		err = a.authenticateRoute(w, r, CookieBasedAuth)
		if err != nil {
			return
		}

		err = a.authenticateRBAC(w, r)
		if err != nil {
			return
		}

		handler(w, r)
	}
}

// AuthenticateRBACHandler is a middleware func that protect the specific route handler using token based authentication and RBAC
func (a *Auth) AuthenticateRBACHandler(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var err error
		err = a.authenticateRoute(w, r, TokenBasedAuth)
		if err != nil {
			return
		}

		err = a.authenticateRBAC(w, r)
		if err != nil {
			return
		}

		handler.ServeHTTP(w, r)
	})
}

// AuthenticateRBACHandlerFunc is a middleware func that protect the specific route handler as HandlerFunc using token based authentication and RBAC
func (a *Auth) AuthenticateRBACHandlerFunc(handler func(w http.ResponseWriter, r *http.Request)) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		var err error
		err = a.authenticateRoute(w, r, TokenBasedAuth)
		if err != nil {
			return
		}

		err = a.authenticateRBAC(w, r)
		if err != nil {
			return
		}

		handler(w, r)
	}
}

// VerifyToken is helper function to get UserID by token string
// This function will get the data from redis database
func (a *Auth) VerifyToken(token string) (int64, error) {
	result, err := a.cacheClient.Do(
		"GET",
		token,
	).Int64()
	if err != nil {
		return -1, err
	}
	return result, nil
}

// GetUserByToken is helper function to get User entity by token string
// This function will get the data from redis and relational databases
func (a *Auth) GetUserByToken(token string) (*schema.User, error) {
	userId, err := a.VerifyToken(token)
	if err != nil {
		return nil, err
	}

	user, err := a.dbSchema.User(nil).FindUser(map[string]interface{}{
		"id": userId,
	})
	if err != nil {
		return nil, ErrUserNotFound
	}
	return user, nil
}

// getUserPrinciple is non exported helper function to get logged user by http request and strategy
func (a *Auth) getUserPrinciple(r *http.Request, strategy int) (*schema.User, error) {
	var token string
	switch strategy {
	case CookieBasedAuth:
		cookieData, err := r.Cookie(a.sessionName)
		if err != nil {
			return nil, ErrInvalidCookie
		}
		token = cookieData.Value
	case TokenBasedAuth:
		rawToken := r.Header.Get(authorization)
		headers := strings.Split(rawToken, " ")
		if len(headers) != 2 {
			return nil, ErrInvalidAuthorization
		}
		token = headers[1]
	}

	userID, err := a.VerifyToken(token)
	if err != nil {
		return nil, ErrValidateCookie
	}
	user, err := a.dbSchema.User(nil).FindUser(map[string]interface{}{
		"id": userID,
	})
	if err != nil {
		return nil, ErrUserNotFound
	}

	return user, nil
}

// GetUserLogin is helper function to get user entity by request
// This function will get the data from specific context
// You should using middleware authentication before call this function
// If not it'll return nil user data
func GetUserLogin(r *http.Request) *schema.User {
	ctx := r.Context()
	return ctx.Value(UserPrinciple).(*schema.User)
}
