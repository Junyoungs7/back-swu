package com.jun.studywithus.oauth2.service;

import com.jun.studywithus.member.model.Member;
import com.jun.studywithus.member.model.SocialType;
import com.jun.studywithus.member.repository.MemberRepository;
import com.jun.studywithus.oauth2.CustomOAuth2User;
import com.jun.studywithus.oauth2.OAuthAttributes;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.util.Collections;
import java.util.Map;


@Service
@Slf4j
@RequiredArgsConstructor
public class CustomOAuth2UserService implements OAuth2UserService<OAuth2UserRequest, OAuth2User> {

    private final MemberRepository memberRepository;

    private static final String NAVER = "naver";
    private static final String KAKAO = "kakao";


    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        log.info("CustomOAuth2UserService.loadUser() 실행 - OAuth2 로그인 요청 진입");

        OAuth2UserService<OAuth2UserRequest, OAuth2User> delegate = new DefaultOAuth2UserService();
        OAuth2User oAuth2User = delegate.loadUser(userRequest);
        String registrationId = userRequest.getClientRegistration().getRegistrationId();
        SocialType socialType = getSocialType(registrationId);
        String userNameAttributeName = userRequest.getClientRegistration().getProviderDetails().getUserInfoEndpoint().getUserNameAttributeName();
        Map<String, Object> attributes = oAuth2User.getAttributes();
        OAuthAttributes extractAttributes = OAuthAttributes.of(socialType, userNameAttributeName, attributes);
        Member createdMember = getMember(extractAttributes, socialType);

        return new CustomOAuth2User(
                Collections.singleton(new SimpleGrantedAuthority(createdMember.getRole().getKey())),
                attributes,
                extractAttributes.getNameAttributeKey(),
                createdMember.getEmail(),
                createdMember.getRole()
        );
    }

    private SocialType getSocialType(String registrationId){
        if(NAVER.equals(registrationId)){
            return SocialType.NAVER;
        }
        if (KAKAO.equals(registrationId)) {
            return SocialType.KAKAO;
        }
        return SocialType.GOOGLE;
    }

    private Member getMember(OAuthAttributes attributes, SocialType socialType){
        Member findMember = memberRepository.findBySocialTypeAndSocialId(socialType, attributes.getOAuth2UserInfo().getId()).orElse(null);

        if (findMember == null) {
            return saveMember(attributes, socialType);
        }
        return findMember;
    }

    private Member saveMember(OAuthAttributes attributes, SocialType socialType){
        Member createdMember = attributes.toEntity(socialType, attributes.getOAuth2UserInfo());
        return memberRepository.save(createdMember);
    }
}
