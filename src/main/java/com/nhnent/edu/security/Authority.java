package com.nhnent.edu.security;

import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.MapsId;
import javax.persistence.OneToOne;
import javax.persistence.Table;
import lombok.Getter;
import lombok.Setter;

// TODO #9: `Authorities` 테이블에 대한 엔티티
@Getter
@Setter
@Entity
@Table(name = "Authorities")
public class Authority {
    @Id
    private String memberId;

    private String authority;


    @MapsId
    @OneToOne
    @JoinColumn(name = "member_id")
    private Member member;

}
