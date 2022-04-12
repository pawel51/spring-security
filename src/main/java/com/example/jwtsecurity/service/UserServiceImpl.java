package com.example.jwtsecurity.service;

import com.example.jwtsecurity.domain.AppUser;
import com.example.jwtsecurity.domain.Role;
import com.example.jwtsecurity.repository.RoleRepository;
import com.example.jwtsecurity.repository.UserRepository;
import com.example.jwtsecurity.utils.enums.RolesEnum;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

//import javax.transaction.Transactional;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

@Service @RequiredArgsConstructor @Transactional
@Slf4j
public class UserServiceImpl implements UserService, UserDetailsService {

    private final UserRepository userRepo;
    private final RoleRepository roleRepo;
    private final PasswordEncoder passwordEncoder;

    @Override
    public UserDetails loadUserByUsername (String username) throws UsernameNotFoundException {
        /*
        Overwrites method, which tells spring how to find a user and his roles
         */
        AppUser user = userRepo.findByUsername(username);
        if (user == null){
            log.error("User not found in database!");
            throw new UsernameNotFoundException("User {} not found in database!");
        }
        else {
            log.info("User {} found in database", user.getUsername());
        }
        Collection<SimpleGrantedAuthority> authorities = new ArrayList<>();
        user.getRoles().forEach(role -> {
            authorities.add(new SimpleGrantedAuthority(role.getName().toString()));
        });
        return new org.springframework.security.core.userdetails.User(user.getUsername(), user.getPassword(), authorities);
    }

    @Override
    public AppUser saveUser (AppUser user) {
        log.info("Adding new user {} to database", user.getName());
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        return userRepo.save(user);
    }

    @Override
    public Role saveRole (Role role) {
        log.info("Adding new role {} to database", role.getName());
        return roleRepo.save(role);
    }

    @Override
    public void addRoleToUser (String username, String roleName) {
        log.info("Adding new role {} to user {}", roleName, username);
        AppUser user = userRepo.findByUsername(username);
        Role role = roleRepo.findByName(RolesEnum.valueOf(roleName));
        user.getRoles().add(role);
    }

    @Override
    public AppUser getUser (String username) {
        log.info("Fetching user {}", username);
        return userRepo.findByUsername(username);
    }

    @Override
    public List<AppUser> getUsers () {
        log.info("Fetching all users");
        return userRepo.findAll();
    }

}
