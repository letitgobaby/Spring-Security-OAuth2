package com.example.letitgobaby.config;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import javax.servlet.Filter;
import javax.servlet.http.HttpServletResponse;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

import com.example.letitgobaby.model.UserRepository;
import com.example.letitgobaby.security.filter.A_LoginFilter;
import com.example.letitgobaby.security.filter.B_LoginFilter;
import com.example.letitgobaby.security.filter.JwtVerifyFilter;
import com.example.letitgobaby.security.filter.dsl.FilterBuilderDsl;
import com.example.letitgobaby.security.provider.A_LoginProvider;
import com.example.letitgobaby.security.provider.JwtVerifyProvider;

import lombok.RequiredArgsConstructor;

// @Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {
  
  private final String[] RESOURCE_URL = new String[] { "/static/**", "/static/css/**", "/js/**", "/images/**","/vendor/**","/fonts/**" };
  private final String[] PERMIT_URL = new String[] { "/login", "/user/login", "/b/login", "/fail", "/test", "/h2", "/h2/**", };

  private final A_LoginProvider aLoginProvider;
  private final JwtVerifyProvider jwtProvider;
  
  @Bean
  public WebSecurityCustomizer webSecurityCustomizer() {
    return (web) -> web.ignoring().antMatchers(RESOURCE_URL);
  }

  @Bean
  public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

    http.httpBasic().disable();
    http.cors();
    http.csrf().disable();
    http.headers().frameOptions().sameOrigin();

    http
      .sessionManagement(sseion -> sseion.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
      .authorizeHttpRequests(authorize -> {
        authorize
          .antMatchers(PERMIT_URL).permitAll()
          .anyRequest().authenticated();
      })
      .exceptionHandling()
      .authenticationEntryPoint((req, res, ex) -> {
        res.sendError(HttpServletResponse.SC_FORBIDDEN, ex.getMessage());
      })
      .accessDeniedHandler((req, res, ex) -> {
        res.sendError(HttpServletResponse.SC_UNAUTHORIZED, ex.getMessage());
      });

    http.apply(filterBuilderDsl());

    return http.build();
  }

  @Bean
  public FilterBuilderDsl filterBuilderDsl() {
    return new FilterBuilderDsl();
  }

  @Bean
  public AuthenticationManager authenticationManager() throws Exception {
    List<AuthenticationProvider> list = Arrays.asList(
      aLoginProvider,
      jwtProvider
    );
    return new ProviderManager(list);
  }

  @Bean
  public CorsFilter corsFilter() {
    UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
    CorsConfiguration config = new CorsConfiguration();
    config.setAllowCredentials(true);
    config.addAllowedOrigin("*");
    config.addAllowedHeader("*");
    config.addAllowedMethod("*");
    source.registerCorsConfiguration("/**", config);
    return new CorsFilter(source);
  }

}
