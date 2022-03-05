package com.example.springsecuritylogin.auth;

import com.example.springsecuritylogin.auth.userInfo.OAuth2UserInfo;
import com.example.springsecuritylogin.domain.User;
import lombok.Getter;
import lombok.ToString;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Map;

@Getter
@ToString
public class PrincipalDetails implements UserDetails, OAuth2User {

    private User user;
    private OAuth2UserInfo oAuth2UserInfo;

    /**
     *  UserDetails : Form 로그인 사용
     */
    public PrincipalDetails(User user) {
        this.user = user;
    }

    /**
     *  OAuth2User : OAuth2 로그인 시 사용
     */
    public PrincipalDetails(User user, OAuth2UserInfo oAuth2UserInfo) {
        this.user = user;
        this.oAuth2UserInfo = oAuth2UserInfo;
    }
//    public PrincipalDetails(User user, Map<String, Object> attributes) {
//        this.user = user;
//        this.attributes = attributes;
//    }

    @Override
    public Map<String, Object> getAttributes() {
        return oAuth2UserInfo.getAttributes();
    }

    /**
     *  UserDetails 구현
     *  해당 유저의 권한목록 리턴
     */
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        Collection<GrantedAuthority> grantedAuthorityCollection = new ArrayList<>();
        grantedAuthorityCollection.add(new GrantedAuthority() {
            @Override
            public String getAuthority() {
                return user.getRole().toString();
            }
        });
        return grantedAuthorityCollection;
    }

    /**
     *  UserDetails 구현
     *  비밀번호를 리턴
     */
    @Override
    public String getPassword() {
        return user.getPassword();
    }

    /**
     *  UserDetails 구현
     *  PK 값을 반환해준다.
     */
    @Override
    public String getUsername() {
        return user.getUsername();
    }

    /**
     *  UserDetails 구현
     *  계정 만료 여부
     *  true : 만료 안 됨
     *  false : 만료됨
     */
    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    /**
     *  UserDetails 구현
     *  계정 잠김 여부
     *  true : 잠기지 않음
     *  false : 잠김
     */
    @Override
    public boolean isAccountNonLocked() {
        return false;
    }

    /**
     *  UserDetails 구현
     *  계정 비밀번호 만료 여부
     *  true : 만료 안됨
     *  false : 만료됨
     */
    @Override
    public boolean isCredentialsNonExpired() {
        return false;
    }

    /**
     *  UserDetails 구현
     *  계정 활성화 여부
     *  true : 활성화됨
     *  false : 활성화 안 됨
     */
    @Override
    public boolean isEnabled() {
        return true;
    }


    /**
     *  OAuth2User 구현
     */
    @Override
    public String getName() {
//        String sub = attributes.get("sub").toString();
//        return sub;
        return oAuth2UserInfo.getProviderId();
    }
}
