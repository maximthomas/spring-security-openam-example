package org.openidentityplatform.openamsecured.configuration;


import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.rememberme.RememberMeAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration
@EnableWebSecurity
public class SecurityConfiguration {

    private final String openAmRealm;
    private final String jwtSecretKey;

    public SecurityConfiguration(@Value("${openam.auth.realm:/}") String openAmRealm,
                                 @Value("${openam.jwt.secret-key}") String jwtSecretKey) {
        this.openAmRealm = openAmRealm;
        this.jwtSecretKey = jwtSecretKey;
    }

    @Bean
    @Order(1)
    @Profile("oauth")
    public SecurityFilterChain securityWebFilterChain(HttpSecurity http) throws Exception {
        http.securityMatcher("/protected-oauth", "/oauth2/**", "/login/oauth2/**").authorizeHttpRequests((authorize) ->
                        authorize.anyRequest().fullyAuthenticated())
                .oauth2Login(Customizer.withDefaults())
                .oauth2Client(Customizer.withDefaults());
        return http.build();
    }

    @Bean
    @Order(2)
    @Profile("saml")
    public SecurityFilterChain securitySamlFilterChain(HttpSecurity http) throws Exception {
        http.securityMatcher("/protected-saml", "/saml2/**", "/login/saml2/**")
                .authorizeHttpRequests((authorize) ->
                        authorize.requestMatchers("/saml2/**").permitAll()
                                .requestMatchers("/protected-saml").fullyAuthenticated())
                .saml2Metadata(Customizer.withDefaults())
                .saml2Login(Customizer.withDefaults());
        return http.build();
    }

    @Bean
    @Order(3)
    @Profile("cookie")
    public SecurityFilterChain securityOpenAmFilterChain(HttpSecurity http) throws Exception {
        http.securityMatcher("/protected-openam")
                .addFilterAt(openAmAuthenticationFilter(), RememberMeAuthenticationFilter.class)
                .authorizeHttpRequests((authorize) ->
                        authorize.anyRequest().fullyAuthenticated())
                .exceptionHandling(e ->
                        e.authenticationEntryPoint((request, response, authException) ->
                                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED)));
        return http.build();
    }

    @Bean
    @Order(4)
    @Profile("jwt")
    public SecurityFilterChain securityJwtFilterChain(HttpSecurity http) throws Exception {
        http.securityMatcher("/protected-jwt", "/api/protected-jwt")
                .addFilterAt(jwtAuthenticationFilter(), RememberMeAuthenticationFilter.class)
                .authorizeHttpRequests((authorize) ->
                        authorize.anyRequest().fullyAuthenticated())
                .exceptionHandling(e ->
                        e.authenticationEntryPoint((request, response, authException) ->
                                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED)));
        return http.build();
    }

    @Bean
    @Order(0)
    public SecurityFilterChain securityPermitAllFilterChain(HttpSecurity http) throws Exception {
        http.securityMatcher("/", "/error", "/logout")
                .authorizeHttpRequests((authorize) -> authorize.anyRequest().permitAll())
                .logout(logout ->
                        logout.logoutSuccessUrl("/?logout")
                                .logoutRequestMatcher(AntPathRequestMatcher.antMatcher("/logout")));

        return http.build();
    }

    public OpenAmAuthenticationFilter openAmAuthenticationFilter() {
        return new OpenAmAuthenticationFilter(openAmRealm, openAmAuthenticationManager());
    }


    public JwtAuthenticationFilter jwtAuthenticationFilter() {
        return new JwtAuthenticationFilter(jwtSecretKey, openAmAuthenticationManager());
    }

    @Bean
    OpenAmAuthenticationManager openAmAuthenticationManager() {
        return new OpenAmAuthenticationManager();
    }
}


