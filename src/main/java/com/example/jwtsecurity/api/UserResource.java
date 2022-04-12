package com.example.jwtsecurity.api;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.example.jwtsecurity.domain.AppUser;
import com.example.jwtsecurity.domain.Role;
import com.example.jwtsecurity.service.UserService;
import com.example.jwtsecurity.utils.TokenUtil;
import com.example.jwtsecurity.utils.enums.RolesEnum;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.stream.Collectors;
import static org.springframework.http.HttpHeaders.AUTHORIZATION;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

@RestController
@RequestMapping("/api")
@RequiredArgsConstructor
@Slf4j
public class UserResource {
    private final UserService userService;

    @GetMapping("/refreshtoken")
    public void refreshToken (HttpServletRequest request, HttpServletResponse response) throws IOException {
        log.info("refresh token procedure started");
        String authorizationHeader = request.getHeader(AUTHORIZATION);
        if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")){
            try {
                TokenUtil tokenUtil = new TokenUtil();
                String refreshToken = authorizationHeader.substring("Bearer ".length());
                // if exception not threw user is already autenticated
                String username = tokenUtil.getUserName(refreshToken).getUserName();
                AppUser user = userService.getUser(username);
                List<String> roles = user.getRoles().stream()
                        .map(Role::getName)
                        .map(RolesEnum::toString)
                        .collect(Collectors.toList());

                String accessToken = tokenUtil.GetToken(request, user, roles, 10);
                tokenUtil.packTokensToFront(response, refreshToken, accessToken);

            } catch (Exception exception) {
                log.error("error loggin in: {}", exception.getMessage());
                response.setHeader("error", exception.getMessage());
                // send error forbiden 403 or
//                    response.sendError(FORBIDDEN.value());
                Map<String, String> error = new HashMap<>();
                error.put("error_message", exception.getMessage());
                response.setContentType(APPLICATION_JSON_VALUE);
                new ObjectMapper().writeValue(response.getOutputStream(), error);
            }
        } else {
            throw new RuntimeException("Refresh token is missing");
        }
    }



    @GetMapping("/users")
    public ResponseEntity<List<AppUser>> getUsers(){
        return ResponseEntity.ok().body(userService.getUsers());
    }

    @PostMapping("/users/save")
    public ResponseEntity<AppUser> saveUser(@RequestBody AppUser user){
        URI uri = URI.create(ServletUriComponentsBuilder.fromCurrentContextPath().path("/api/user/save").toUriString());
        return ResponseEntity.created(uri).body(userService.saveUser(user));
    }

    @PostMapping("/role/save")
    public ResponseEntity<Role> saveRole(@RequestBody Role role){
        URI uri = URI.create(ServletUriComponentsBuilder.fromCurrentContextPath().path("/api/role/save").toUriString());
        return ResponseEntity.created(uri).body(userService.saveRole(role));
    }

    @PostMapping("/role/addtouser")
    public ResponseEntity<?> addRolToUser(@RequestBody RoleToUserForm form){
        userService.addRoleToUser(form.getUsername(), form.getRolename());
        return ResponseEntity.ok().build();
    }


}

@Data
class RoleToUserForm {
    private String username;
    private String rolename;
}