package com.tfb.authgw.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.ldap.core.support.LdapContextSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.ldap.authentication.BindAuthenticator;
import org.springframework.security.ldap.authentication.LdapAuthenticationProvider;
import org.springframework.security.ldap.search.FilterBasedLdapUserSearch;
import org.springframework.security.ldap.userdetails.DefaultLdapAuthoritiesPopulator;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Value("${ldap.enabled:true}")
    private boolean ldapEnabled;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http, AuthSuccessHandler authSuccessHandler)
            throws Exception {
        http
                .authorizeHttpRequests(authz -> authz
                        .requestMatchers("/css/**", "/js/**", "/images/**").permitAll()
                        .anyRequest().authenticated())
                .formLogin(form -> form
                        .loginPage("/login")
                        .successHandler(authSuccessHandler)
                        .permitAll())
                .logout(logout -> logout
                        //.permitAll());
                        .logoutUrl("/logout")          // 指定登出 URL
                        .logoutSuccessUrl("/login?logout")    // 登出後導向
                        .invalidateHttpSession(true)          // 清除 session
                        .deleteCookies("JSESSIONID"));        // 清除 cookie
        return http.build();
    }

    @Bean
    public AuthenticationManager authenticationManager(HttpSecurity http) throws Exception {
        AuthenticationManagerBuilder authenticationManagerBuilder = http
                .getSharedObject(AuthenticationManagerBuilder.class);
        if (ldapEnabled) {
            try {
                LdapContextSource contextSource = new LdapContextSource();
                contextSource.setUrl("ldap://localhost:389");
                contextSource.setBase("dc=example,dc=com");
                contextSource.afterPropertiesSet();

                FilterBasedLdapUserSearch userSearch = new FilterBasedLdapUserSearch(
                        "ou=users", "(uid={0})", contextSource);
                userSearch.setSearchSubtree(true);

                BindAuthenticator bindAuthenticator = new BindAuthenticator(contextSource);
                bindAuthenticator.setUserSearch(userSearch);

                DefaultLdapAuthoritiesPopulator authoritiesPopulator = new DefaultLdapAuthoritiesPopulator(
                        contextSource, "ou=groups");
                authoritiesPopulator.setGroupRoleAttribute("cn");
                authoritiesPopulator.setSearchSubtree(true);

                LdapAuthenticationProvider ldapProvider = new LdapAuthenticationProvider(bindAuthenticator,
                        authoritiesPopulator);
                authenticationManagerBuilder.authenticationProvider(ldapProvider);
            } catch (Exception e) {
                // Fallback to in-memory if LDAP fails
                authenticationManagerBuilder.userDetailsService(userDetailsService());
            }
        } else {
            authenticationManagerBuilder.userDetailsService(userDetailsService());
        }
        return authenticationManagerBuilder.build();
    }

    @Bean
    public UserDetailsService userDetailsService() {
        UserDetails user = User.withUsername("user")
                .password(passwordEncoder().encode("password"))
                .roles("USER")
                .build();
        return new InMemoryUserDetailsManager(user);
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}