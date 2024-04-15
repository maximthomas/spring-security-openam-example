package org.openidentityplatform.openamsecured.configuration;

import com.google.common.primitives.Bytes;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.apache.commons.lang3.StringUtils;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

public class JwtAuthenticationFilter extends BasicAuthenticationFilter {

    public static final String AUTH_HEADER_PREFIX = "Bearer ";
    public static final String AUTH_HEADER = "Authorization";

    private final String jwtSecretKey;

    public JwtAuthenticationFilter(String jwtSecretKey, AuthenticationManager authenticationManager) {
        super(authenticationManager);
        this.jwtSecretKey = jwtSecretKey;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String authHeader = request.getHeader(AUTH_HEADER);
        if (StringUtils.isEmpty(authHeader) || !StringUtils.startsWith(authHeader, AUTH_HEADER_PREFIX)) {
            response.sendError(401);
            return;
        }
        final String sub;
        try {
            String jwtStr = authHeader.substring(AUTH_HEADER_PREFIX.length());
            Jws<Claims> jwt = Jwts.parser()
                    .verifyWith(getSigningKey()).build()
                    .parseSignedClaims(jwtStr)
                    .accept(Jws.CLAIMS);
            sub = jwt.getPayload().getSubject();
        } catch (Exception e) {
            logger.warn("error parsing JWT", e);
            response.sendError(401);
            return;
        }

        OpenAmAuthenticationToken token = new OpenAmAuthenticationToken(sub);
        SecurityContextHolder.getContext().setAuthentication(getAuthenticationManager().authenticate(token));
        filterChain.doFilter(request, response);
    }


    private SecretKey getSigningKey() {
        byte[] keyBytes = this.jwtSecretKey.getBytes(StandardCharsets.UTF_8);
        keyBytes = Bytes.ensureCapacity(keyBytes , 256/8, 0);
        String jwtAlg = "HMACSHA256";
        return new SecretKeySpec(keyBytes, jwtAlg);
    }
}
