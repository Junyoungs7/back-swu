package com.jun.studywithus.jwt.service;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.jun.studywithus.member.repository.MemberRepository;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Date;
import java.util.Optional;

@Service
@RequiredArgsConstructor
@Getter
@Slf4j
public class JwtService {

    @Value("${jwt.secretKey}")
    private String secretKey;

    @Value("${jwt.access.expiration}")
    private Long accessTokenExpirationPeriod;

    @Value("${jwt.refresh.expiration}")
    private Long refreshTokenExpirationPeriod;

    @Value("${jwt.access.header}")
    private String accessHeader;

    @Value("${jwt.refresh.header}")
    private String refreshHeader;

    private static final String ACCESS_TOKEN_SUBJECT = "AccessToken";
    private static final String REFRESH_TOKEN_SUBJECT = "RefreshToken";
    private static final String EMAIL_CLAIM = "email";
    private static final String BEARER = "Bearer ";

    private final MemberRepository memberRepository;

    // 토큰 생성

    public String createAccessToken(String email){
        Date now = new Date();
        return JWT.create()
                .withSubject(ACCESS_TOKEN_SUBJECT)
                .withExpiresAt(new Date(now.getTime() + accessTokenExpirationPeriod))
                .withClaim(EMAIL_CLAIM, email)
                .sign(Algorithm.HMAC512(secretKey));
    }

    public String createRefreshToken(){
        Date now = new Date();
        return JWT.create()
                .withSubject(REFRESH_TOKEN_SUBJECT)
                .withExpiresAt(new Date(now.getTime() + refreshTokenExpirationPeriod))
                .sign(Algorithm.HMAC512(secretKey));
    }

    // 헤더에 토큰 넣기

    public void sendAccessToken(HttpServletResponse response, String accessToken){
        response.setStatus(HttpServletResponse.SC_OK);
        response.setHeader(accessHeader, accessToken);
        log.info("재발급된 Access Token : {}", accessToken);
    }

    public void sendAccessAndRefreshToken(HttpServletResponse response, String accessToken, String refreshToken){
        response.setStatus(HttpServletResponse.SC_OK);
        response.setHeader(accessHeader, accessToken);
        response.setHeader(refreshHeader, refreshToken);
        log.info("Access Token, Refresh Token 헤더 설정 완료");
    }

    // 헤더에서 토큰 추출
    public Optional<String> extractRefreshToken(HttpServletRequest request){
        return Optional.ofNullable(request.getHeader(refreshHeader))
                .filter(refreshToken -> refreshToken.startsWith(BEARER))
                .map(refreshToken -> refreshToken.replace(BEARER, ""));
    }

    public Optional<String> extractAccessToken(HttpServletRequest request){
        return Optional.ofNullable(request.getHeader(accessHeader))
                .filter(accessToken -> accessToken.startsWith(BEARER))
                .map(accessToken -> accessToken.replace(BEARER, ""));
    }

    /**
     * AccessToken 에서 Email 추출
     * 추출 전에 JWT.require()로 검증기 생성
     * verify 로 AccessToken 검증 후
     * 유효하다면 getClaim()으로 이메일 추출
     * 유효하지 않다면 빈 Optional 객체 반환
     */
    public Optional<String> extractEmail(String accessToken){
        try{
            return Optional.ofNullable(JWT.require(Algorithm.HMAC512(secretKey))
                    .build()
                    .verify(accessToken)
                    .getClaim(EMAIL_CLAIM)
                    .asString());
        }catch (Exception e){
            log.error("액세스 토큰이 유효하지 않습니다.");
            return Optional.empty();
        }
    }

    // 헤더 설정
    public void setAccessTokenHeader(HttpServletResponse response, String accessToken){
        response.setHeader(accessHeader, accessToken);
    }

    public void setRefreshTokenHeader(HttpServletResponse response, String refreshToken){
        response.setHeader(refreshHeader, refreshToken);
    }

    // refreshToken 저장 및 업데이트
    public void updateRefreshToken(String email, String refreshToken){
        memberRepository.findByEmail(email)
                .ifPresentOrElse(member -> member.updateRefreshToken(refreshToken), () -> new Exception("일치하는 회원이 없습니다."));
    }

    public boolean isTokenValid(String token){
        try{
            JWT.require(Algorithm.HMAC512(secretKey)).build().verify(token);
            return true;
        }catch (Exception e){
            log.error("유효하지 않은 토큰입니다. {}", e.getMessage());
            return false;
        }
    }
}
