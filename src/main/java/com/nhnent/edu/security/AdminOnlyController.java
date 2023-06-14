package com.nhnent.edu.security;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

// TODO : #1 ADMIN 만 접근 가능한 페이지 `/admin-only'를 추가.
@Controller
@RequestMapping("/admin-only")
public class AdminOnlyController {
    private final AdminOnlyService adminOnlyService;


    public AdminOnlyController(AdminOnlyService adminOnlyService) {
        this.adminOnlyService = adminOnlyService;
    }


    @GetMapping
    public String adminOnly(Model model) {
        // TODO : #2 거기에는 ADMIN만 접근 가능한 데이터가 있음.
        model.addAttribute("data", adminOnlyService.getDataOnlyAdminCanAccess());

        return "admin-only";
    }

}
