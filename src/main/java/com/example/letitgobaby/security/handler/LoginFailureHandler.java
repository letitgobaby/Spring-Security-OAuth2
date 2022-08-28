package com.example.letitgobaby.security.handler;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;

import com.example.letitgobaby.web.apis.results.ApiResult;
import com.fasterxml.jackson.databind.ObjectMapper;

import lombok.extern.slf4j.Slf4j;

@Slf4j
public class LoginFailureHandler implements AuthenticationFailureHandler {

  @Override
  public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
      AuthenticationException exception) throws IOException, ServletException {
    log.info("## LoginFailureHandler ##");

    int sc = HttpStatus.BAD_REQUEST.value();
    response.setStatus(sc);
    response.setContentType(MediaType.APPLICATION_JSON_VALUE);
    response.setHeader("Cache-Control", "no-cache, no-store, must-revalidate");
    response.setDateHeader("Expires", 0);
    new ObjectMapper().writeValue(response.getWriter(), new ApiResult(sc, exception.getMessage()));
    response.getWriter().flush();
  }
  
}
