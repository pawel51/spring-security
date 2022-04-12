package com.example.jwtsecurity.repository;

import com.example.jwtsecurity.domain.Role;
import com.example.jwtsecurity.utils.enums.RolesEnum;
import org.springframework.data.jpa.repository.JpaRepository;

public interface RoleRepository extends JpaRepository<Role, Long> {
    Role findByName(RolesEnum roleName);
}
