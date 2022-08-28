package com.example.letitgobaby.web.apis;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestController;

import com.example.letitgobaby.exceptions.SignUpException;
import com.example.letitgobaby.web.apis.results.ExceptionResult;

@ControllerAdvice
@RestController
public class GlobalExceptionAdvisor {
  
  @ExceptionHandler(SignUpException.class)
  public ResponseEntity<ExceptionResult> signUpException(SignUpException exception) {
    HttpStatus status = HttpStatus.BAD_REQUEST;
    ExceptionResult result = new ExceptionResult(exception.getMessage(), status);
    return new ResponseEntity<ExceptionResult>(result, status);
  }
  
}
