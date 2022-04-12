package com.example.jwtsecurity.domain;


import lombok.*;

import javax.persistence.*;
import java.util.ArrayList;
import java.util.Collection;



@Entity
@Table
@Getter @Setter
@NoArgsConstructor
@AllArgsConstructor
public class AppUser {
    @Id
    @SequenceGenerator(name = "user_sequence", sequenceName = "user_sequence", allocationSize = 1)
    @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "user_sequence")
    private Long id;
    private String name;
    private String username;
    private String password;
    // load all roles whenever i load user
    @ManyToMany(fetch = FetchType.EAGER)
    private Collection<Role> roles = new ArrayList<>();
}
