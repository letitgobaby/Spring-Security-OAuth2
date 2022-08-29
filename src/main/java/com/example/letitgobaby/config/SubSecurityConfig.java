package com.example.letitgobaby.config;

import java.util.Arrays;

import javax.servlet.Filter;

import org.springframework.context.annotation.Bean;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import com.example.letitgobaby.security.filter.sub.SubAuthorizeFilter;
import com.example.letitgobaby.security.filter.sub.SubJwtVerifyFilter;
import com.example.letitgobaby.security.filter.sub.SubLoginFilter;
import com.example.letitgobaby.security.handler.LoginFailureHandler;
import com.example.letitgobaby.security.handler.LoginSuccessHandler;
import com.example.letitgobaby.security.provider.LoginProcessProvider;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@EnableWebSecurity
@RequiredArgsConstructor
public class SubSecurityConfig {

  private final LoginProcessProvider loginProvider;

  @Bean
  @Order(1)
  public SecurityFilterChain subFilterChain(HttpSecurity http) throws Exception {

    http.httpBasic().disable();
    http.csrf().disable();
    http.headers().frameOptions().disable();
    http.cors().configurationSource(corsConfigurationSource());
    http.sessionManagement(sseion -> sseion.sessionCreationPolicy(SessionCreationPolicy.STATELESS));

    http.antMatcher("/sub/**");
    http.authorizeHttpRequests(authorize -> {
      authorize.anyRequest().permitAll();
    });


    http.exceptionHandling((handle) -> {
      handle.accessDeniedHandler((req, res, ex) -> {
        res.sendError(HttpStatus.FORBIDDEN.value(), ex.getMessage());
      });
      handle.authenticationEntryPoint((req, res, ex) -> {
        res.sendError(HttpStatus.UNAUTHORIZED.value(), ex.getMessage());
      });
    });

    AuthenticationManagerBuilder authManagerBuilder = http.getSharedObject(AuthenticationManagerBuilder.class);
    authManagerBuilder.authenticationProvider(loginProvider);
    AuthenticationManager aManager = authManagerBuilder.build();

    http.authenticationManager(aManager);
    http.addFilterBefore(subLoginFilter(aManager), UsernamePasswordAuthenticationFilter.class);
    http.addFilterAt(new SubJwtVerifyFilter(aManager), UsernamePasswordAuthenticationFilter.class);
    return http.build();
  }

  public Filter subAuthrizeFilter(AuthenticationManager authenticationManager) {
    String LOGIN_URL = "/sub/authorize";
    RequestMatcher login_requestMatcher = new AntPathRequestMatcher(LOGIN_URL, HttpMethod.GET.name());
    SubAuthorizeFilter filter = new SubAuthorizeFilter(login_requestMatcher, authenticationManager);
    filter.setAuthenticationSuccessHandler(new LoginSuccessHandler());
    filter.setAuthenticationFailureHandler(new LoginFailureHandler());
    return filter;
  }

  public Filter subLoginFilter(AuthenticationManager authenticationManager) {
    String LOGIN_URL = "/sub/login";
    RequestMatcher login_requestMatcher = new AntPathRequestMatcher(LOGIN_URL, HttpMethod.GET.name());
    SubLoginFilter filter = new SubLoginFilter(login_requestMatcher, authenticationManager);
    filter.setAuthenticationSuccessHandler(new LoginSuccessHandler());
    filter.setAuthenticationFailureHandler(new LoginFailureHandler());
    return filter;
  }

  public CorsConfigurationSource corsConfigurationSource() {
    UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();  
    CorsConfiguration config = new CorsConfiguration();
    config.setAllowCredentials(true);
    config.setAllowedOriginPatterns(Arrays.asList("*"));
    config.setAllowedMethods(Arrays.asList("OPTIONS", "GET"));
    config.addAllowedHeader("Authorization");
    source.registerCorsConfiguration("/**", config);
    return source;
  }

}
