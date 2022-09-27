package com.example.letitgobaby.model;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.Table;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data @Builder
@AllArgsConstructor @NoArgsConstructor
@Entity
@Table(name = "sub_login")
public class SubLogin {
  
  @Id
  @Column(name = "id")
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  private Long id;

  @Column(name = "client_id")
  private String clientId;

  @Column(name = "redirect_uri")
  private String redirectUri;

  @Column(name = "code")
  private String code;

  @Column(name = "user_token")
  private String userToken;

  @Column(name = "allow_scope")
  private String allowScope;
  
}
