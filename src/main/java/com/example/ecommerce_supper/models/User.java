package com.example.ecommerce_supper.models;

import jakarta.persistence.*;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

import java.time.LocalDateTime;
import java.util.HashSet;
import java.util.Set;

@Entity
@Table(name = "users",
        uniqueConstraints = {
                @UniqueConstraint(columnNames = "username"),
                @UniqueConstraint(columnNames = "phone")
        })
public class User {
  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  private Long id;

  @NotBlank
  @Size(max = 20)
  private String username;

  @NotBlank
  @Size(max = 12)
  private String phone;
  private boolean isOnline;

  @NotBlank
  @Size(max = 120)
  private String password;
  private boolean isBanned;
  @Lob
  private String image;
  @ManyToMany(fetch = FetchType.LAZY)
  @JoinTable(  name = "user_roles",
          joinColumns = @JoinColumn(name = "user_id"),
          inverseJoinColumns = @JoinColumn(name = "role_id"))
  private Set<Role> roles = new HashSet<>();

  public User() {
  }

  public User(String username, String phone, boolean isBanned, String password, String image) {
    this.username = username;
    this.phone = phone;
    this.password = password;
    this.image = image;
    this.isBanned = isBanned;
  }

  public User(String username, String phone, String password, boolean isBanned, Set<Role> roles ) {
    this.username = username;
    this.phone = phone;
    this.password = password;
    this.isBanned = isBanned;
    this.roles = roles;
  }

  public User(String username, String phone, boolean isOnline, String password,  boolean isBanned, String image, Set<Role> roles) {
    this.username = username;
    this.phone = phone;
    this.isOnline = isOnline;
    this.password = password;
    this.isBanned = isBanned;
    this.image = image;
    this.roles = roles;
  }

  public Long getId() {
    return id;
  }

  public void setId(Long id) {
    this.id = id;
  }

  public String getUsername() {
    return username;
  }

  public void setUsername(String username) {
    this.username = username;
  }

  public String getPhone() {
    return phone;
  }


  public boolean isBanned() {
    return isBanned;
  }

  public void setBanned(boolean banned) {
    isBanned = banned;
  }

  public void setPhone(String phone) {
    this.phone = phone;
  }

  public boolean isOnline() {
    return isOnline;
  }

  public void setOnline(boolean online) {
    isOnline = online;
  }

  public String getPassword() {
    return password;
  }

  public void setPassword(String password) {
    this.password = password;
  }

  public Set<Role> getRoles() {
    return roles;
  }

  public void setRoles(Set<Role> roles) {
    this.roles = roles;
  }


  public String getImage() {
    return image;
  }

  public void setImage(String image) {
    this.image = image;
  }
}