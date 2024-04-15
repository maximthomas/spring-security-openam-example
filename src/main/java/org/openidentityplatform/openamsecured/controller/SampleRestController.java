package org.openidentityplatform.openamsecured.controller;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/api")
public class SampleRestController {

    @GetMapping("/protected-jwt")
    public Map<String, String> jwtProtected(@AuthenticationPrincipal String principal) {
        return Map.of("user", principal, "method", "JWT");
    }
}
