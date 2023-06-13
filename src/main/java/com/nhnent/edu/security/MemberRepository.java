package com.nhnent.edu.security;

import org.springframework.data.jpa.repository.JpaRepository;

// TODO #10: Member 엔티티에 대한 Repository
public interface MemberRepository extends JpaRepository<Member, String> {
}
