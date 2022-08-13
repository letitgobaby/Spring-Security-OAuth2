package com.example.letitgobaby.model;

import java.time.LocalDateTime;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.Table;

import org.hibernate.annotations.CreationTimestamp;

import lombok.Data;

@Data
@Entity
@Table(name = "user")
public class User {
  
  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  private Long id;

  @Column(name = "user_id")
  private String userId;

  @Column(name = "password")
  private String password;

  @Column(name = "name")
  private String name;

  @Column(name = "role")
  private String role;

  @CreationTimestamp
  @Column(name = "created_at")
  private LocalDateTime createdAt;

}
