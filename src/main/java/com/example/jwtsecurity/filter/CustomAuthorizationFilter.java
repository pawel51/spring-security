package com.example.jwtsecurity.filter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.example.jwtsecurity.utils.TokenUtil;
import com.example.jwtsecurity.utils.UserRoles;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.*;

import static java.util.Arrays.stream;
import static org.springframework.http.HttpHeaders.AUTHORIZATION;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

@Slf4j
public class CustomAuthorizationFilter extends OncePerRequestFilter {
    @Override
    protected void doFilterInternal (HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        // everytime request comes to api
        if (request.getServletPath().equals("/api/login") || request.getServletPath().equals("/api/refreshtoken")){
            try {
                filterChain.doFilter(request, response);
            } catch (Exception e){
                log.error("filterchain.dofilter threw exception {}", e.getMessage());
            }
        }
        else {
            String authorizationHeader = request.getHeader(AUTHORIZATION);
            if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")){
                authorize(request, response, filterChain, authorizationHeader);
            } else {
                filterChain.doFilter(request, response);
            }
        }
    }

    private void authorize (HttpServletRequest request, HttpServletResponse response, FilterChain filterChain, String authorizationHeader) throws IOException {
        try {
            TokenUtil tokenUtil = new TokenUtil();
            String token = authorizationHeader.substring(7);
            UserRoles userRoles = tokenUtil.getUserNameAndRole(token);
            // if exception not threw user is already autenticated
            String username = userRoles.getUserName();
            String[] roles = userRoles.getRoles();
            SetAccesToEndpoints(username, roles);
            filterChain.doFilter(request, response);

        } catch (Exception exception) {
            log.error("Error logging in: {}", exception.getMessage());
            response.setHeader("Error", exception.getMessage());
            // send error forbiden 403 or
//                    response.sendError(FORBIDDEN.value());
            Map<String, String> error = new HashMap<>();
            error.put("error_message", exception.getMessage());
            response.setContentType(APPLICATION_JSON_VALUE);
            new ObjectMapper().writeValue(response.getOutputStream(), error);
        }
    }

    private void SetAccesToEndpoints (String username, String[] roles) {
        Collection<SimpleGrantedAuthority> authorities = new ArrayList<>();
        if (roles != null){
            stream(roles).forEach(role -> {
                authorities.add(new SimpleGrantedAuthority(role));
            });
        }

        UsernamePasswordAuthenticationToken authenticationToken =
                new UsernamePasswordAuthenticationToken(username, null, authorities);
        SecurityContextHolder.getContext().setAuthentication(authenticationToken);
    }


}
