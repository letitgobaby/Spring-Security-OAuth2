package com.example.letitgobaby.security.exception;

import org.springframework.security.core.AuthenticationException;

public class LoginAuthenticationException extends AuthenticationException {
  public LoginAuthenticationException(String msg) {
    super(msg);
  }
}
