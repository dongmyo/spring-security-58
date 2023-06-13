package com.nhnent.edu.security;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class MemberRestController {
    private final MemberService memberService;


    public MemberRestController(MemberService memberService) {
        this.memberService = memberService;
    }


    @PostMapping("/members")
    public String createMember(@RequestBody MemberCreateRequest request) {
        return memberService.createMember(request);
    }

}
