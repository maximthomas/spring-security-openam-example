package org.openidentityplatform.openamsecured.controller;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticatedPrincipal;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class SampleController {

    @GetMapping
    public String index() {
        return "index";
    }

    @GetMapping("/protected-oauth")
    public String oauthProtected(Model model, @AuthenticationPrincipal OAuth2AuthenticatedPrincipal principal) {
        model.addAttribute("userName", principal.getName());
        model.addAttribute("method", "OAuth2/OIDC");
        return "protected";
    }

    @GetMapping("/protected-saml")
    public String samlProtected(Model model, @AuthenticationPrincipal Saml2AuthenticatedPrincipal principal) {
        String emailAddress = principal.getFirstAttribute("email");
        model.addAttribute("userName", emailAddress);
        model.addAttribute("method", "SAMLv2");
        return "protected";
    }

    @GetMapping("/protected-openam")
    public String cookieProtected(Model model,  @AuthenticationPrincipal String principal) {
        model.addAttribute("userName", principal);
        model.addAttribute("method", "OpenAM Cookie");
        return "protected";
    }

    @GetMapping("/protected-jwt")
    public String jwtProtected(Model model, @AuthenticationPrincipal String principal) {
        model.addAttribute("userName", principal);
        model.addAttribute("method", "JWT");
        return "protected";
    }
}
