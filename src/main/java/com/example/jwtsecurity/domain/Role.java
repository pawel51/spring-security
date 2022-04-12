package com.example.jwtsecurity.domain;

import com.example.jwtsecurity.utils.enums.RolesEnum;
import lombok.*;

import javax.persistence.*;

@Entity
@Table
@Getter @Setter
@NoArgsConstructor
@AllArgsConstructor
public class Role {
    @Id
    @SequenceGenerator(name = "role_sequence", sequenceName = "role_sequence", allocationSize = 1)
    @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "role_sequence")
    private Long id;
    private RolesEnum name;
}
