package com.nhnent.edu.security;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
@RequestMapping("/admin-only")
public class AdminOnlyController {
    private final AdminOnlyService adminOnlyService;


    public AdminOnlyController(AdminOnlyService adminOnlyService) {
        this.adminOnlyService = adminOnlyService;
    }


    @GetMapping
    public String adminOnly(Model model) {
        model.addAttribute("data", adminOnlyService.getDataOnlyAdminCanAccess());

        return "admin-only";
    }

}
