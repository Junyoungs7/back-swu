package com.jun.studywithus.member.dto;

import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

import javax.validation.constraints.NotNull;

@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class MemberSignUpDto {

    @NotNull
    private String email;
    @NotNull
    private String password;
    @NotNull
    private String nickname;

}
