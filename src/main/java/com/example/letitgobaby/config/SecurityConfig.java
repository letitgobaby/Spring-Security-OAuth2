package com.example.letitgobaby.config;

import java.util.ArrayList;
import java.util.List;

import javax.servlet.Filter;
import javax.servlet.http.HttpServletResponse;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
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
import com.example.letitgobaby.security.provider.A_LoginProvider;

import lombok.RequiredArgsConstructor;

// @Configuration
@EnableWebSecurity(debug = true)
@RequiredArgsConstructor
public class SecurityConfig {
  
  private final String[] RESOURCE_URL = new String[] { "/resources/**", "/static/**", "/static/css/**", "/js/**", "/images/**","/vendor/**","/fonts/**" };
  private final String[] PERMIT_URL = new String[] { "/login", "/user/login", "/fail", "/h2", "/h2/**", };

  private final A_LoginProvider aLoginProvider;
  // private final UserRepository userRepository;

  private AuthenticationManager authenticationManager;

  private ProviderManager providerManagerByLogin;
  private List<AuthenticationProvider> providerListByLogin = new ArrayList<>();

  @Bean
  public WebSecurityCustomizer webSecurityCustomizer() {
    return (web) -> web.ignoring().antMatchers(RESOURCE_URL);
  }

  @Bean
  public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    
    // setupProviders();

    http.httpBasic().disable();

    http.cors();
    http.csrf().disable();
    http.headers().frameOptions().sameOrigin();

    // http.formLogin()
    //   .loginProcessingUrl("/user/login")
    //   .usernameParameter("userId")
    //   .passwordParameter("pswd")
    //   .defaultSuccessUrl("/test")
    //   .failureForwardUrl("/fail");

    http
      .sessionManagement(sseion -> sseion.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
      .requestMatchers(matchers -> matchers.antMatchers("/static/**"))
      .authorizeHttpRequests(authorize -> {
        authorize
          .antMatchers(PERMIT_URL).permitAll()
          .anyRequest().authenticated();
      })
      .exceptionHandling()
      .authenticationEntryPoint((req, res, ex) -> {
        System.out.println("nnnn");
        res.sendError(HttpServletResponse.SC_FORBIDDEN, ex.getMessage());
      })
      .accessDeniedHandler((req, res, ex) -> {
        res.sendError(HttpServletResponse.SC_UNAUTHORIZED, ex.getMessage());
      });

    AuthenticationManagerBuilder authenticationManagerBuilder = http.getSharedObject(AuthenticationManagerBuilder.class);
    authenticationManagerBuilder.authenticationProvider(this.aLoginProvider);
    this.authenticationManager = authenticationManagerBuilder.build();
    

    // http.authenticationManager(this.authenticationManager);
    http.authenticationProvider(this.aLoginProvider);

    

    http
      // .addFilterBefore(a_LoginFilter(), UsernamePasswordAuthenticationFilter.class)
      .addFilterBefore(b_LoginFilter(this.authenticationManager), UsernamePasswordAuthenticationFilter.class);

    

    return http.build();
  }

  @Bean
  public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
    return authenticationConfiguration.getAuthenticationManager();
  }


  // @Bean
  public Filter b_LoginFilter(AuthenticationManager authenticationManager) {
    // String LOGIN_URL = "/b/login";
    // RequestMatcher login_requestMatcher = new AntPathRequestMatcher(LOGIN_URL, HttpMethod.POST.name());
    B_LoginFilter loginFilter = new B_LoginFilter(authenticationManager);
    // loginFilter.setAuthenticationManager(authenticationManager);
    return loginFilter;
  }

  // @Bean
  // public UserDetailsService userDetailsService() {
  //   return new A_LoginProvider(this.userRepository);
  // }

  // @Bean
  // public A_LoginProvider aLoginProvider() {
  //   return new A_LoginProvider(this.userRepository);
  // }

  // private Filter a_LoginFilter() {
  //   String LOGIN_URL = "/a/login";
  //   RequestMatcher login_requestMatcher = new AntPathRequestMatcher(LOGIN_URL, HttpMethod.GET.name());
  //   A_LoginFilter loginFilter = new A_LoginFilter(login_requestMatcher);
  //   loginFilter.setAuthenticationManager(getAuthManagerForLogin());
  //   return loginFilter;
  // }


  // @Bean
  // public AuthenticationManager getAuthManagerForLogin() {
  //   if (this.providerManagerByLogin == null) {
  //     this.providerManagerByLogin = new ProviderManager(this.providerListByLogin);
  //   }
  //   return this.providerManagerByLogin;
  // }

  // @Bean
  // public void setupProviders() {
  //   // A_LoginProvider aProvider = new A_LoginProvider(this.userRepository);
  //   this.providerListByLogin.add(this.aLoginProvider);
    
  //   // 
  // }

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

  @Bean
  public PasswordEncoder bCryptPasswordEncoder() {
    return new BCryptPasswordEncoder();
  }

}
