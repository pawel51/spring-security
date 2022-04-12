package com.example.jwtsecurity.utils;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.example.jwtsecurity.domain.AppUser;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;


public class TokenUtil {
    public static final Algorithm ALGORITHM = Algorithm.HMAC256("secret".getBytes());



    public String GetRefreshToken (HttpServletRequest request, User user, int minutes) {
        return JWT.create()
                .withSubject(user.getUsername())
                .withExpiresAt(new Date(System.currentTimeMillis() + (long) minutes * 60 * 1000))
                .withIssuer(request.getRequestURL().toString())
                .sign(ALGORITHM);
    }

    public String GetToken (HttpServletRequest request, User user, List<String> roles, int minutes) {
        return JWT.create()
                .withSubject(user.getUsername())
                .withExpiresAt(new Date(System.currentTimeMillis() + (long) minutes * 60 * 1000))
                .withIssuer(request.getRequestURL().toString())
                .withClaim("roles", roles)
                .sign(ALGORITHM);
    }
    public String GetToken (HttpServletRequest request, AppUser user, List<String> roles, int minutes) {
        return JWT.create()
                .withSubject(user.getUsername())
                .withExpiresAt(new Date(System.currentTimeMillis() + (long) minutes * 60 * 1000))
                .withIssuer(request.getRequestURL().toString())
                .withClaim("roles", roles)
                .sign(ALGORITHM);
    }
    public DecodedJWT getDecodedJWT (String token) {
        JWTVerifier verifier = JWT.require(ALGORITHM).build();
        return verifier.verify(token);
    }

    public UserRoles getUserName (String token) {
        JWTVerifier verifier = JWT.require(ALGORITHM).build();
        DecodedJWT decodedJWT = verifier.verify(token);
        return new UserRoles(decodedJWT.getSubject(), null);
    }

    public UserRoles getUserNameAndRole (String token) {
        JWTVerifier verifier = JWT.require(ALGORITHM).build();
        DecodedJWT decodedJWT = verifier.verify(token);
        return new UserRoles(decodedJWT.getSubject(), decodedJWT.getClaim("roles").asArray(String.class));
    }

    public void packTokensToFront (HttpServletResponse response, String accessToken, String refreshToken) throws IOException {
        Map<String, String> tokens = new HashMap<>();
        tokens.put("access_token", accessToken);
        tokens.put("refresh_token", refreshToken);
        response.setContentType(APPLICATION_JSON_VALUE);
        new ObjectMapper().writeValue(response.getOutputStream(), tokens);
    }

}
