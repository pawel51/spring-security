package com.example.jwtsecurity.utils;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;

import java.util.ArrayList;
import java.util.List;

@Getter @Setter @AllArgsConstructor
public class UserRoles {
    private String userName;
    String[] roles;
}
