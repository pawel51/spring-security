package com.example.jwtsecurity;

import com.example.jwtsecurity.domain.AppUser;
import com.example.jwtsecurity.domain.Role;
import com.example.jwtsecurity.service.UserService;
import com.example.jwtsecurity.utils.enums.RolesEnum;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.ArrayList;

import static com.example.jwtsecurity.utils.enums.RolesEnum.ROLE_MANAGER;
import static com.example.jwtsecurity.utils.enums.RolesEnum.ROLE_USER;

@SpringBootApplication
public class JwtSecurityApplication {

    public static void main (String[] args) {
        SpringApplication.run(JwtSecurityApplication.class, args);
    }

    @Bean
    PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

    @Bean
    CommandLineRunner run(UserService userService){
        return args -> {
            userService.saveRole(new Role(null, ROLE_USER));
            userService.saveRole(new Role(null, RolesEnum.ROLE_MANAGER));
            userService.saveRole(new Role(null, RolesEnum.ROLE_ADMIN));
            userService.saveRole(new Role(null, RolesEnum.ROLE_SUPERADMIN));

            userService.saveUser(new AppUser(null, "John Travolta", "john", "1234", new ArrayList<>()));
            userService.saveUser(new AppUser(null, "Bruce Willic", "butch", "1234", new ArrayList<>()));
            userService.saveUser(new AppUser(null, "Katy Parry", "katy", "1234", new ArrayList<>()));
            userService.saveUser(new AppUser(null, "Uma Thurman", "uma", "1234", new ArrayList<>()));

            userService.addRoleToUser("john", ROLE_USER.toString());
            userService.addRoleToUser("john", ROLE_MANAGER.toString());
            userService.addRoleToUser("uma", ROLE_USER.toString());
        };
    }
}
