package com.example.letitgobaby.security.exception;

import org.springframework.security.core.AuthenticationException;

public class SubAuthenticationException extends AuthenticationException {
  public SubAuthenticationException(String msg) {
    super(msg);
  }
}
