package com.jun.studywithus.member.controller;

import com.jun.studywithus.member.dto.MemberSignUpDto;
import com.jun.studywithus.member.service.MemberService;
import lombok.RequiredArgsConstructor;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import javax.validation.Valid;

@RestController
@RequiredArgsConstructor
public class MemberController {

    private final MemberService memberService;

    @PostMapping("/sign-up")
    public String signUp(@Valid @RequestBody MemberSignUpDto memberSignUpDto, BindingResult bindingResult){
        if (bindingResult.hasErrors()) {
            return "이메일, 패스워드, 이름을 다시 한번 확인해주세요.";
        }
        try{
            memberService.signUp(memberSignUpDto);
            return "회원가입 성공";
        } catch (Exception e) {
            return e.getMessage();
        }
    }

    @GetMapping("/jwt-test")
    public String jwtTest(){
        return "jwtTest 요청 성공";
    }
}
