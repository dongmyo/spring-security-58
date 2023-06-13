package com.nhnent.edu.security;

import javax.persistence.CascadeType;
import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.OneToOne;
import javax.persistence.Table;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@Entity
@Table(name = "Members")
public class Member {
    @Id
    @Column(name = "member_id")
    private String id;

    private String name;

    private String pwd;


    @OneToOne(mappedBy = "member", cascade = { CascadeType.PERSIST, CascadeType.MERGE })
    private Authority authority;

}
