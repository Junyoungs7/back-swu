package com.jun.studywithus.oauth2;

import com.jun.studywithus.member.model.Member;
import com.jun.studywithus.member.model.Role;
import com.jun.studywithus.member.model.SocialType;
import com.jun.studywithus.oauth2.userinfo.GoogleOAuth2UserInfo;
import com.jun.studywithus.oauth2.userinfo.KakaoOAuth2UserInfo;
import com.jun.studywithus.oauth2.userinfo.NaverOAuth2UserInfo;
import com.jun.studywithus.oauth2.userinfo.OAuth2UserInfo;
import lombok.Builder;
import lombok.Getter;

import java.util.Map;
import java.util.UUID;

@Getter
public class OAuthAttributes {

    private String nameAttributeKey;
    private OAuth2UserInfo oAuth2UserInfo;

    @Builder
    public OAuthAttributes(String nameAttributeKey, OAuth2UserInfo oAuth2UserInfo){
        this.nameAttributeKey = nameAttributeKey;
        this.oAuth2UserInfo = oAuth2UserInfo;
    }

    public static OAuthAttributes of(SocialType socialType, String userNameAttributeName, Map<String, Object> attributes){
        if (socialType == SocialType.NAVER) {
            return ofNaver(userNameAttributeName, attributes);
        }
        if (socialType == SocialType.KAKAO) {
            return ofKakao(userNameAttributeName, attributes);
        }
        return ofGoogle(userNameAttributeName, attributes);
    }

    public static OAuthAttributes ofNaver(String userNameAttributeName, Map<String, Object> attributes){
        return OAuthAttributes.builder()
                .nameAttributeKey(userNameAttributeName)
                .oAuth2UserInfo(new NaverOAuth2UserInfo(attributes))
                .build();
    }

    public static OAuthAttributes ofKakao(String userNameAttributeName, Map<String, Object> attributes){
        return OAuthAttributes.builder()
                .nameAttributeKey(userNameAttributeName)
                .oAuth2UserInfo(new KakaoOAuth2UserInfo(attributes))
                .build();
    }

    public static OAuthAttributes ofGoogle(String userNameAttributeName, Map<String, Object> attributes){
        return OAuthAttributes.builder()
                .nameAttributeKey(userNameAttributeName)
                .oAuth2UserInfo(new GoogleOAuth2UserInfo(attributes))
                .build();
    }

    public Member toEntity(SocialType socialType, OAuth2UserInfo oAuth2UserInfo){
        return Member.builder()
                .socialType(socialType)
                .socialId(oAuth2UserInfo.getId())
                .email(UUID.randomUUID() + "@socialUser.com")
                .nickname(oAuth2UserInfo.getNickname())
                .imageUrl(oAuth2UserInfo.getImageUrl())
                .role(Role.GUEST)
                .build();
    }
}
