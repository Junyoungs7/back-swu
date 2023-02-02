package com.jun.studywithus.member.service;

import com.jun.studywithus.member.dto.MemberSignUpDto;
import com.jun.studywithus.member.model.Member;
import com.jun.studywithus.member.model.Role;
import com.jun.studywithus.member.repository.MemberRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class MemberService {

    private final MemberRepository memberRepository;
    private final PasswordEncoder passwordEncoder;

    public void signUp(MemberSignUpDto memberSignUpDto) throws Exception {
        if (memberRepository.existsByEmail(memberSignUpDto.getEmail())) {
            throw new Exception("이미 존재하는 이메일입니다.");
        }
        Member member = Member.builder()
                .email(memberSignUpDto.getEmail())
                .password(memberSignUpDto.getPassword())
                .nickname(memberSignUpDto.getNickname())
                .role(Role.USER)
                .build();

        member.passwordEncode(passwordEncoder);
        memberRepository.save(member);
    }

}
