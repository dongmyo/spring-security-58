package com.nhnent.edu.security;

import java.util.Collections;
import java.util.List;
import java.util.Optional;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

// TODO #4: Custom UserDetailsService 빈
@Service
public class CustomUserDetailsService implements UserDetailsService {
    private final MemberRepository memberRepository;


    public CustomUserDetailsService(MemberRepository memberRepository) {
        this.memberRepository = memberRepository;
    }


    // TODO #5: `loadUserByUsername()` 메서드 구현
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Optional<Member> optionalMember = memberRepository.findById(username);
        if (optionalMember.isEmpty()) {
            throw new UsernameNotFoundException(username + " is not found");
        }

        Member member = optionalMember.get();

        List<GrantedAuthority> authorities = Collections.singletonList(new SimpleGrantedAuthority(
            member.getAuthority().getAuthority()));

        return new User(member.getName(), member.getPwd(), authorities);
    }

}
