package org.openidentityplatform.openamsecured.configuration;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.web.client.RestTemplate;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Stream;

public class OpenAmAuthenticationFilter extends BasicAuthenticationFilter {

    private final String openAmUrl = "http://openam.example.org:8080/openam";
    private final String openAuthUrl = openAmUrl.concat("/XUI/");

    private final String openAmRealm;

    private final String openAmUserInfoUrl = openAmUrl.concat("/json/users?_action=idFromSession");
    private final String openAmCookieName = "iPlanetDirectoryPro";

    private final String redirectUrl = "http://app.example.org:8081/protected-openam";

    public OpenAmAuthenticationFilter(String openAmRealm, AuthenticationManager authenticationManager) {
        super(authenticationManager);
        this.openAmRealm = openAmRealm;
    }
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        Optional<Cookie> openamCookie =
                (request.getCookies() != null ? Arrays.stream(request.getCookies()) : Stream.<Cookie>empty())
                .filter(c -> c.getName().equals(openAmCookieName)).findFirst();
        if(openamCookie.isEmpty()) {
            response.sendRedirect(openAuthUrl + "?goto=" + URLEncoder.encode(redirectUrl, StandardCharsets.UTF_8)
                    + "&realm=".concat(URLEncoder.encode(openAmRealm, StandardCharsets.UTF_8)));
        } else {
            String userId = getUserIdFromSession(openamCookie.get().getValue());
            if (userId == null) {
                throw new BadCredentialsException("invalid session!");
            }
            OpenAmAuthenticationToken token = new OpenAmAuthenticationToken(userId);
            SecurityContextHolder.getContext().setAuthentication(getAuthenticationManager().authenticate(token));
            filterChain.doFilter(request, response);
        }
    }

    protected String getUserIdFromSession(String sessionId) {
        RestTemplate restTemplate = new RestTemplate();
        ParameterizedTypeReference<Map<String, String>> responseType =
                new ParameterizedTypeReference<>() {};
        HttpHeaders headers = new HttpHeaders();
        headers.add(openAmCookieName, sessionId);
        headers.setContentType(MediaType.APPLICATION_JSON);
        HttpEntity<?> entity = new HttpEntity<>(headers);
        ResponseEntity<Map<String, String>> response = restTemplate.exchange(openAmUserInfoUrl, HttpMethod.POST, entity, responseType);
        Map<String, String> body = response.getBody();
        if (body == null) {
            return null;
        }
        return body.get("id");
    }
}
