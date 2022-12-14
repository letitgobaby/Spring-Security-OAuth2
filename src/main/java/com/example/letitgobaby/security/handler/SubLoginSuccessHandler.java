package com.example.letitgobaby.security.handler;

import java.io.IOException;
import java.net.URI;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import com.example.letitgobaby.security.token.AuthUserToken;
import com.example.letitgobaby.security.token.sub.AuthGrantToken;
import com.example.letitgobaby.web.apis.results.ApiResult;
import com.fasterxml.jackson.databind.ObjectMapper;

import lombok.extern.slf4j.Slf4j;

@Slf4j
public class SubLoginSuccessHandler implements AuthenticationSuccessHandler {
  
  @Override
  public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
      Authentication authentication) throws IOException, ServletException {
    log.info("## LoginSuccessHandler ##");

    AuthGrantToken auth = (AuthGrantToken) authentication;

    Map<String, String> body = new HashMap<>();
    body.put("tokenType", "Bearer");
    body.put("accessToken", auth.getAccessToken());
    body.put("refreshToken", auth.getRefreshToken());

    response.setStatus(HttpStatus.OK.value());
    response.setContentType(MediaType.APPLICATION_JSON_VALUE);
    response.setHeader("Cache-Control", "no-cache, no-store, must-revalidate");
    response.setDateHeader("Expires", 0);
    new ObjectMapper().writeValue(response.getWriter(), new ApiResult(HttpStatus.OK.value(), "SUB-LOGIN").body(body));
    response.getWriter().flush();
  }
  
}
