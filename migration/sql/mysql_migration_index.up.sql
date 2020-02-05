-- create index
CREATE UNIQUE INDEX `rbac_user_email_idx` ON rbac_user(email);
CREATE UNIQUE INDEX `rbac_user_username_idx` ON rbac_user(username);
CREATE UNIQUE INDEX `rbac_permission_route_method_idx` ON rbac_permission(route, method);
CREATE UNIQUE INDEX `rbac_permission_name_idx` ON rbac_permission(name);
CREATE UNIQUE INDEX `rbac_role_name_idx` ON rbac_role(name);
CREATE UNIQUE INDEX `rbac_user_role_role_user_idx` on rbac_user_role (role_id, user_id);
CREATE UNIQUE INDEX `rbac_role_permission_role_permission_idx` on rbac_role_permission (role_id, permission_id);
CREATE UNIQUE INDEX `rbac_role_rbac_rule_idx` ON rbac_rule (name, rule_type, parent_id);
CREATE INDEX `rbac_role_rbac_rule_checker_idx` ON rbac_rule (rule_type, parent_id);
