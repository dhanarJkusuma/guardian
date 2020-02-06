## Guardian
RBAC Auth library for GoLang.

## Install

```console
go get github.com/dhanarJkusuma/guardian
```


## What is Guardian?
Guardian is a library that used for create RBAC authentication. This library inspired by Yii2 RBAC Framework.
This library contains entity `users`, `permissions`, `roles`, and `rules`. Every resource is associated with `permissions`. 
Every permissions is grouped by `roles`. One `user` can has many of `role`. One more entity is  `rules`, it'll add additional constraint to `roles` and `permissions` 



## How to Use
### Initialize Guardian

Examples:
```go
        // open db connection
	dbConn := fmt.Sprintf("%s:%s@tcp(%s)/%s?parseTime=true&multiStatements=true", "root", "", "127.0.0.1", "guard_example")
	db, err := sql.Open("mysql", dbConn)
	if err != nil {
		panic(err.Error())
	}
	defer db.Close()

	// init redis
	cacheClient := redis.NewClient(&redis.Options{
		Addr:     "localhost:6379",
		Password: "",
	})

	// init guardian
	guard := guardian.NewGuardian(&guardian.Options{
		DbConnection: db,
		SchemaName:   "guard_example",
		Session: guardian.SessionOptions{
			CacheClient:      cacheClient,
			LoginMethod:      auth.LoginEmail,
			ExpiredInSeconds: int64(24 * time.Hour),
			SessionName:      "_Guardian_Session_",
		},
	}).Build()

	// init db migration
	err = guard.Migration.Initialize()
	if err != nil {
		panic(err.Error())
	}
```
Guardian need dbConnection, and redis to store the authentication data and session. For database connection string, need to add
 `parseTime=true` and `multiStatements=true`, it's required to db schema migration, and parseTime from db.

After guardian is initialized, it'll return struct that has exported attribute `Auth` and `Migration`. `Auth` provide
all func for authentication. Then `Migration` provide all func to init db schema and do some custom migration.
When func below is called. Then `guardian` will create db_schema for you.
```go
        // init db migration
	err = guard.Migration.Initialize()
	if err != nil {
		panic(err.Error())
	}
```

### Running Custom Migration
```go
        // run migration for user registration
	err = guard.Migration.Run("some_user", func(g *migration.GuardTx) error {
		// inject guardTx with user schema
		user := g.User(&schema.User{
			Username: "someuser",
			Email:    "someuser@guardian.com",
			Password: "onlysecret",
		})
		// create another user without role
		return g.Auth.Register(user)
	})
	if err != nil && err != migration.ErrMigrationAlreadyExist {
		panic(err)
	}
```
You can make custom migration by calling Run() function. This function belongs to Migration struct.
if you want to run custom migration you should write migration `name` uniquely, otherwise your migration won't be executed.


### Protect the HTTP Route
```go
        r := mux.NewRouter()
	r.HandleFunc("/login", handler.LoginHandler).Methods(http.MethodPost)
	r.HandleFunc("/rahasia", guard.Auth.AuthenticateRBACHandlerFunc(handler.PrivateHandler)).Methods(http.MethodGet)
	r.HandleFunc("/dashboard", guard.Auth.AuthenticateHandlerFunc(handler.DashboardHandler)).Methods(http.MethodGet)

	log.Fatal(http.ListenAndServe(":8000", r))
```
You can protect your HTTP route by adding middleware like snippet above.

### Authentication
For authentication, you can use functions belongs to `Auth` entity.
For Example:
```go
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

```
SignIn method will return loggedUser, token, and error. Token is used to authenticate user login, by `Authorization` header.
After you get the token, you can try to access private route using header `Authorization` with value `Bearer <token>`

### Define a Rule
If you want to define some `rule`, you can add the rules constrain in the database.
```go
        // run migration for create dashboard route and rule
	err = guard.Migration.Run("dashboard_rule", func(g *migration.GuardTx) error {
		var errMig error

		// create permission
		dashboardPermission := &schema.Permission{
			Name:   "dashboard_owner",
			Method: http.MethodGet,
			Route:  "/dashboard",
		}
		errMig = g.Permission(dashboardPermission).Save()
		if errMig != nil {
			return errMig
		}

		// create rule
		dashboardRule := &schema.Rule{
			RuleType: schema.EnumRuleTypes.PermissionRuleType,
			ParentID: dashboardPermission.ID,
			Name:     "rule_dashboard_owner",
		}
		errMig = g.Rule(dashboardRule).Save()
		if errMig != nil {
			return errMig
		}
		return nil
	})
```
Then, create a `rule` function using RuleExecutor interface that need to implement `Name()` and `Execute(*schema.User, *rule.schema.Rule, r *http.Request)` function
```go
type DashboardRule struct {
	// could contains database connection or something
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

```
After that, register `rule` function using `Auth.RegisterRule()`
```go
        // register the rule
	guard.Auth.RegisterRule(&DashboardRule{})
```