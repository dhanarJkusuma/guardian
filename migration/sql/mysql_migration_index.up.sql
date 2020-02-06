-- create index
CREATE UNIQUE INDEX `guard_user_email_idx` ON guard_user(email);
CREATE UNIQUE INDEX `guard_user_username_idx` ON guard_user(username);
CREATE UNIQUE INDEX `guard_permission_route_method_idx` ON guard_permission(route, method);
CREATE UNIQUE INDEX `guard_permission_name_idx` ON guard_permission(name);
CREATE UNIQUE INDEX `guard_role_name_idx` ON guard_role(name);
CREATE UNIQUE INDEX `guard_user_role_role_user_idx` on guard_user_role (role_id, user_id);
CREATE UNIQUE INDEX `guard_role_permission_role_permission_idx` on guard_role_permission (role_id, permission_id);
CREATE UNIQUE INDEX `guard_role_guard_rule_idx` ON guard_rule (name, rule_type, parent_id);
CREATE INDEX `guard_role_guard_rule_checker_idx` ON guard_rule (rule_type, parent_id);
