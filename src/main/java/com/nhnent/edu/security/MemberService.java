package com.nhnent.edu.security;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class MemberService {
    private final MemberRepository memberRepository;
    private final PasswordEncoder passwordEncoder;


    public MemberService(MemberRepository memberRepository, PasswordEncoder passwordEncoder) {
        this.memberRepository = memberRepository;
        this.passwordEncoder = passwordEncoder;
    }


    @Transactional
    public String createMember(MemberCreateRequest request) {
        Member member = new Member();
        member.setId(request.getId());
        member.setName(request.getName());
        member.setPwd(passwordEncoder.encode(request.getPwd()));

        Authority authority = new Authority();
        authority.setMember(member);
        authority.setAuthority(request.getAuthority());

        member.setAuthority(authority);

        memberRepository.saveAndFlush(member);

        return member.getId();
    }

}
