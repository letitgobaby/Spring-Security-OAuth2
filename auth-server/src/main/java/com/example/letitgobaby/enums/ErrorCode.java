package com.example.letitgobaby.enums;

public enum ErrorCode {
  
  USER_NOT_FOUND("User Not Found"), 
  USER_ALREADY_EXIST("User already exists");

  private final String value;

  ErrorCode(String value) { 
    this.value = value; 
  }

  public String getValue() { 
    return value; 
  }

}
