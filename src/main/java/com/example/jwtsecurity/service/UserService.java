package com.example.jwtsecurity.service;

import com.example.jwtsecurity.domain.AppUser;
import com.example.jwtsecurity.domain.Role;
import com.example.jwtsecurity.utils.enums.RolesEnum;

import java.util.List;

public interface UserService {
    AppUser saveUser(AppUser user);
    Role saveRole(Role role);
    void addRoleToUser(String username, String roleName);
    AppUser getUser(String username);
    List<AppUser> getUsers();
}
