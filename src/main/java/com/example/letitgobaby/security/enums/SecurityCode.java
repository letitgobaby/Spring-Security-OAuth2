package com.example.letitgobaby.security.enums;

public enum SecurityCode {

  USER_NOT_FOUND("User Not Found"), 
  BAD_CREDENTIAL("Bad Credential"), 
  
  TOKEN_NOT_FOUND("Token Not Found"), 
  TOKEN_EXPIRED("Token Expired");

  private final String value;

  SecurityCode(String value) { 
    this.value = value; 
  }

  public String getValue() { 
    return value; 
  }
}
