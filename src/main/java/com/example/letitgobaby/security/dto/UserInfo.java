package com.example.letitgobaby.security.dto;

import java.io.Serializable;

import com.example.letitgobaby.model.User;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data @Builder @NoArgsConstructor @AllArgsConstructor
public class UserInfo implements Serializable {

  private static final long serialVersionUID = 1L;

  private Long id;
  private String userId;
  private String userName;
  private String userRole;

  public UserInfo toDto(User user) {
    return UserInfo.builder()
      .id(user.getId())
      .userId(user.getUserId())
      .userName(user.getUserName())
      .userRole(user.getUserRole())
      .build();
  }

}
