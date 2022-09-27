package com.example.letitgobaby.web.apis.results;

import lombok.Getter;

@Getter
public class ApiResult {
  
  private int status;
  private String message;
  private Object data;

  public ApiResult() { }
  public ApiResult(int status, String message) {
    this.status = status;
    this.message = message;
  }
  
  public ApiResult body(Object data) {
    this.data = data;
    return this;
  }

}
