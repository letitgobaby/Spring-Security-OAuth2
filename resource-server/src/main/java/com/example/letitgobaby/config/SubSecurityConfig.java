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
import com.example.letitgobaby.security.filter.sub.SubConsentFilter;
import com.example.letitgobaby.security.filter.sub.SubJwtVerifyFilter;
import com.example.letitgobaby.security.filter.sub.SubLoginFilter;
import com.example.letitgobaby.security.filter.sub.SubAuthGrantFilter;
import com.example.letitgobaby.security.handler.LoginFailureHandler;
import com.example.letitgobaby.security.handler.LoginSuccessHandler;
import com.example.letitgobaby.security.handler.SubLoginSuccessHandler;
import com.example.letitgobaby.security.provider.LoginProcessProvider;
import com.example.letitgobaby.security.provider.sub.SubAuthorizeProvider;
import com.example.letitgobaby.security.provider.sub.SubAutoLoginProcessProvider;
import com.example.letitgobaby.security.provider.sub.SubConsentProvider;
import com.example.letitgobaby.security.provider.sub.SubLoginProcessProvider;
import com.example.letitgobaby.security.provider.sub.SubAuthGrantProvider;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@EnableWebSecurity
@RequiredArgsConstructor
public class SubSecurityConfig {

  private final SubAutoLoginProcessProvider autoLoginProcessProvider;
  private final SubLoginProcessProvider loginProvider;
  private final SubAuthGrantProvider grantProvider;
  private final SubAuthorizeProvider authorizeProvider;
  private final SubConsentProvider consentProvider;

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
      authorize
        .antMatchers("/sub/loginpage", "/sub/consent").permitAll()
        .anyRequest().authenticated();
    });


    http.exceptionHandling((handle) -> {
      handle.authenticationEntryPoint((req, res, ex) -> {
        res.sendRedirect("/sub/authorize?" + req.getQueryString());
      });
      handle.accessDeniedHandler((req, res, ex) -> {
        res.sendError(HttpStatus.FORBIDDEN.value(), ex.getMessage());
      });
    });

    AuthenticationManagerBuilder authManagerBuilder = http.getSharedObject(AuthenticationManagerBuilder.class);
    authManagerBuilder.authenticationProvider(autoLoginProcessProvider);
    authManagerBuilder.authenticationProvider(loginProvider);
    authManagerBuilder.authenticationProvider(grantProvider);
    authManagerBuilder.authenticationProvider(authorizeProvider);
    authManagerBuilder.authenticationProvider(consentProvider);
    AuthenticationManager aManager = authManagerBuilder.build();

    http.authenticationManager(aManager);
    http.addFilterBefore(subAuthrizeFilter(aManager), UsernamePasswordAuthenticationFilter.class);
    http.addFilterBefore(subConsentFilter(aManager), UsernamePasswordAuthenticationFilter.class);
    http.addFilterBefore(subTokenFilter(aManager), UsernamePasswordAuthenticationFilter.class);
    http.addFilterAt(subLoginFilter(aManager), UsernamePasswordAuthenticationFilter.class);
    return http.build();
  }

  public Filter subAuthrizeFilter(AuthenticationManager authenticationManager) {
    String REQUEST_URL = "/sub/authorize";
    RequestMatcher login_requestMatcher = new AntPathRequestMatcher(REQUEST_URL, HttpMethod.GET.name());
    SubAuthorizeFilter filter = new SubAuthorizeFilter(login_requestMatcher, authenticationManager);
    filter.setAuthenticationFailureHandler(new LoginFailureHandler());
    return filter;
  }

  public Filter subConsentFilter(AuthenticationManager authenticationManager) {
    String REQUEST_URL = "/sub/code";
    RequestMatcher login_requestMatcher = new AntPathRequestMatcher(REQUEST_URL, HttpMethod.GET.name());
    SubConsentFilter filter = new SubConsentFilter(login_requestMatcher, authenticationManager);
    filter.setAuthenticationFailureHandler(new LoginFailureHandler());
    return filter;
  }

  public Filter subLoginFilter(AuthenticationManager authenticationManager) {
    String LOGIN_URL = "/sub/login";
    RequestMatcher login_requestMatcher = new AntPathRequestMatcher(LOGIN_URL, HttpMethod.POST.name());
    SubLoginFilter filter = new SubLoginFilter(login_requestMatcher, authenticationManager);
    filter.setAuthenticationSuccessHandler(new LoginSuccessHandler());
    filter.setAuthenticationFailureHandler(new LoginFailureHandler());
    return filter;
  }

  public Filter subTokenFilter(AuthenticationManager authenticationManager) {
    String REQUEST_URL = "/sub/token";
    RequestMatcher login_requestMatcher = new AntPathRequestMatcher(REQUEST_URL, HttpMethod.POST.name());
    SubAuthGrantFilter filter = new SubAuthGrantFilter(login_requestMatcher, authenticationManager);
    filter.setAuthenticationSuccessHandler(new SubLoginSuccessHandler());
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
