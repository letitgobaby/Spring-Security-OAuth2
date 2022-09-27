package com.example.letitgobaby.web.apis.results;

import org.springframework.http.HttpStatus;

public class ExceptionResult {
  
  private int status;
  private String message;
  private Object data;

  public ExceptionResult(String message, HttpStatus httpStatus) {
    this.message = message;
    this.status = httpStatus.value();
  }

  public int getStatus() {
    return status;
  }
  
  public String getMessage() {
    return message;
  }

  public Object getData() {
    return data;
  }

}
