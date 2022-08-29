package com.example.letitgobaby.config;

import java.util.Arrays;

import javax.servlet.Filter;
import javax.servlet.http.HttpServletResponse;

import org.springframework.context.annotation.Bean;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

import com.example.letitgobaby.security.filter.MainLoginFilter;
import com.example.letitgobaby.security.filter.SubLoginFilter;
import com.example.letitgobaby.security.filter.JwtVerifyFilter;
import com.example.letitgobaby.security.filter.RefreshTokenFilter;
import com.example.letitgobaby.security.handler.JwtFailureHandler;
import com.example.letitgobaby.security.handler.LoginFailureHandler;
import com.example.letitgobaby.security.handler.LoginSuccessHandler;
import com.example.letitgobaby.security.provider.JwtVerifyProvider;
import com.example.letitgobaby.security.provider.LoginProcessProvider;
import com.example.letitgobaby.security.provider.ReGenerateTokenProvider;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {
  
  private final String[] RESOURCE_URL = new String[] { "/static/**", "/favicon.ico", "/js/**", "/images/**", "/css/**", "/fonts/**" };
  private final String[] SUB_PERMIT_URL = new String[] { "/sub/login", "/refresh/token" };
  private final String[] AUTHENTICATE_PERMIT_URL = new String[] { "/main/login", "/user/signUp", "/refresh/token" };
  private final String[] PERMIT_URL = new String[] { "/login", "/fail", "/test", "/h2", "/h2/**", "/user/test" };

  private final LoginProcessProvider loginProvider;
  private final JwtVerifyProvider jwtProvider;
  private final ReGenerateTokenProvider regenProvider;
  
  @Bean
  public WebSecurityCustomizer webSecurityCustomizer() {
    return (web) -> web.ignoring().antMatchers(RESOURCE_URL);
  }

  @Bean
  // @Order(1)
  public SecurityFilterChain mainfilterChain(HttpSecurity http) throws Exception {

    http.httpBasic().disable();
    http.cors().configurationSource(mainCorsConfig());
    http.csrf().disable();
    http.headers().frameOptions().sameOrigin();

    http
      .sessionManagement(sseion -> sseion.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
      .authorizeHttpRequests(authorize -> {
        authorize
          .antMatchers(AUTHENTICATE_PERMIT_URL).permitAll()
          .antMatchers(PERMIT_URL).permitAll()
          .antMatchers("/user/auth/test").hasAnyRole("USER")
          .anyRequest().authenticated();
      })
      .exceptionHandling()
      .authenticationEntryPoint((req, res, ex) -> {
        log.error("authenticationEntryPoint " + ex.getClass().getName() + " = " + ex.getMessage());
        res.sendRedirect("/login");
      })
      .accessDeniedHandler((req, res, ex) -> {
        log.error("accessDeniedHandler - " + ex.getClass().getName() + " = " + ex.getMessage());
        res.sendError(HttpServletResponse.SC_UNAUTHORIZED, ex.getMessage());
      });


    AuthenticationManagerBuilder authManagerBuilder = http.getSharedObject(AuthenticationManagerBuilder.class);
    AuthenticationManager aManager = toProviders(authManagerBuilder);
    http.authenticationManager(aManager);

    http.addFilterBefore(mainLoginFilter(aManager), UsernamePasswordAuthenticationFilter.class);
    http.addFilterBefore(reGenFilter(aManager), UsernamePasswordAuthenticationFilter.class);
    http.addFilterAt(jwtFilter(aManager), UsernamePasswordAuthenticationFilter.class);

    return http.build();
  }


  // @Bean
  // @Order(1)
  // public SecurityFilterChain subFilterChain(HttpSecurity http) throws Exception {

  //   http.httpBasic().disable();
  //   http.csrf().disable();
  //   http.headers().frameOptions().disable();
  //   http.cors().configurationSource(corsConfigurationSource());

  //   AuthenticationManagerBuilder authManagerBuilder = http.getSharedObject(AuthenticationManagerBuilder.class);
  //   authManagerBuilder.authenticationProvider(loginProvider);
  //   AuthenticationManager aManager = authManagerBuilder.build();

  //   http.authenticationManager(aManager);
  //   http.addFilterBefore(subLoginFilter(aManager), UsernamePasswordAuthenticationFilter.class);
  //   return http.build();
  // }


  public Filter mainLoginFilter(AuthenticationManager authenticationManager) {
    String LOGIN_URL = "/main/login";
    RequestMatcher login_requestMatcher = new AntPathRequestMatcher(LOGIN_URL, HttpMethod.POST.name());
    MainLoginFilter filter = new MainLoginFilter(login_requestMatcher, authenticationManager);
    filter.setAuthenticationSuccessHandler(new LoginSuccessHandler());
    filter.setAuthenticationFailureHandler(new LoginFailureHandler());
    return filter;
  }

  public Filter subLoginFilter(AuthenticationManager authenticationManager) {
    String LOGIN_URL = "/b/login";
    RequestMatcher login_requestMatcher = new AntPathRequestMatcher(LOGIN_URL, HttpMethod.GET.name());
    SubLoginFilter filter = new SubLoginFilter(login_requestMatcher, authenticationManager);
    filter.setAuthenticationSuccessHandler(new LoginSuccessHandler());
    filter.setAuthenticationFailureHandler(new LoginFailureHandler());
    return filter;
  }

  public Filter reGenFilter(AuthenticationManager authenticationManager) {
    String LOGIN_URL = "/refresh/token";
    RequestMatcher requestMatcher = new AntPathRequestMatcher(LOGIN_URL, HttpMethod.GET.name());
    RefreshTokenFilter filter = new RefreshTokenFilter(requestMatcher, authenticationManager);
    filter.setAuthenticationSuccessHandler(new LoginSuccessHandler());
    filter.setAuthenticationFailureHandler(new LoginFailureHandler());
    return filter;
  }

  public Filter jwtFilter(AuthenticationManager authenticationManager) {
    JwtVerifyFilter filter = new JwtVerifyFilter();
    filter.setAuthenticationManager(authenticationManager);
    filter.setAuthenticationFailureHandler(new JwtFailureHandler());
    return filter;
  }

  public AuthenticationManager toProviders(AuthenticationManagerBuilder builder) throws Exception {
    builder.authenticationProvider(loginProvider);
    builder.authenticationProvider(jwtProvider);
    builder.authenticationProvider(regenProvider);

    return builder.eraseCredentials(true).build();
  }



  // @Bean
  // public CorsFilter corsFilter() {
  //   UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
  //   CorsConfiguration config = new CorsConfiguration();
  //   config.setAllowCredentials(true);
  //   config.addAllowedOrigin("*");
  //   config.addAllowedHeader("*");
  //   config.addAllowedMethod("*");
  //   source.registerCorsConfiguration("/**", config);
  //   return new CorsFilter(source);
  // }

  @Bean
  public CorsConfigurationSource mainCorsConfig() {
    UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();  
    CorsConfiguration configuration = new CorsConfiguration();
    configuration.setAllowCredentials(true);
    configuration.setAllowedOrigins(Arrays.asList("http://localhost:8080"));
    configuration.setAllowedMethods(Arrays.asList("POST"));
    // configuration.addAllowedHeader("*");
    source.registerCorsConfiguration("/**", configuration);
    return source;
  }

}
