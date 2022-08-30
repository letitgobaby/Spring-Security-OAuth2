package com.example.letitgobaby.model;

import java.time.LocalDateTime;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.Table;

import org.hibernate.annotations.CreationTimestamp;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data @Builder
@AllArgsConstructor @NoArgsConstructor
@Entity
@Table(name = "client_info")
public class ClientInfo {
  
  @Id
  @Column(name = "id")
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  private Long id;

  @Column(name = "client_id", length = 9999)
  private String clientId;

  @Column(name = "client_secret", length = 9999)
  private String clientSecret;

  @CreationTimestamp
  @Column(name = "created_at")
  private LocalDateTime createdAt;

}
